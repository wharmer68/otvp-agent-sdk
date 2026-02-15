#!/usr/bin/env python3
"""
OTVP Reference Agent: Vulnerability Management

Checks SSM patch compliance and Inspector findings.
Maps to SOC 2 CC7.1 | ISO 27001 A.12.6.1 | NIST CSF DE.CM-8

Usage:
    export AWS_PROFILE=otvp-test
    python run_vuln_agent.py
"""
from __future__ import annotations

import asyncio
import argparse
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import boto3
from botocore.exceptions import ClientError
from otvp_agent import Agent, AgentConfig, KeyPair, Evidence
from otvp_agent.agents import Collector, CollectionContext, EvaluationResult
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.aws_vuln")


class VulnManagementCollector(Collector):
    domain = "infrastructure.compute.vulnerability_management"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        region = context.region or "us-east-2"
        evidence_items = []

        # Check SSM managed instances and patch compliance
        try:
            ssm = boto3.client("ssm", region_name=region)
            instances = ssm.describe_instance_information().get("InstanceInformationList", [])

            for inst in instances:
                instance_id = inst.get("InstanceId", "unknown")
                platform = inst.get("PlatformType", "unknown")
                ping_status = inst.get("PingStatus", "unknown")

                # Get patch compliance
                compliant_count = 0
                non_compliant_count = 0
                critical_missing = 0
                try:
                    comp = ssm.list_compliance_items(
                        Filters=[{"Key": "ComplianceType", "Values": ["Patch"], "Type": "EQUAL"}],
                        ResourceIds=[instance_id], ResourceTypes=["ManagedInstance"])
                    for item in comp.get("ComplianceItems", []):
                        status = item.get("Status", "")
                        severity = item.get("Severity", "")
                        if status == "COMPLIANT":
                            compliant_count += 1
                        else:
                            non_compliant_count += 1
                            if severity in ("CRITICAL", "HIGH"):
                                critical_missing += 1
                except ClientError:
                    pass

                is_compliant = non_compliant_count == 0 and ping_status == "Online"

                evidence_items.append(self.observe(
                    resource=f"arn:aws:ec2:{region}::instance/{instance_id}",
                    property="PatchCompliant", value=is_compliant, expected=True,
                    metadata={"instance_id": instance_id, "platform": platform,
                              "ping_status": ping_status, "patches_compliant": compliant_count,
                              "patches_non_compliant": non_compliant_count,
                              "critical_missing": critical_missing, "source": "ssm"},
                    api="ssm:DescribeInstanceInformation,ssm:ListComplianceItems", region=region))

        except ClientError as e:
            logger.info(f"SSM not available or no managed instances: {e}")

        # Check Inspector findings
        try:
            inspector = boto3.client("inspector2", region_name=region)
            # Get summary of findings by severity
            findings = inspector.list_findings(
                filterCriteria={"findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]},
                maxResults=100
            ).get("findings", [])

            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in findings:
                sev = f.get("severity", "LOW")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            has_critical = severity_counts.get("CRITICAL", 0) > 0
            total_findings = sum(severity_counts.values())

            evidence_items.append(self.observe(
                resource=f"arn:aws:inspector2:{region}::findings",
                property="NoActiveCriticalFindings", value=not has_critical, expected=True,
                metadata={"total_active_findings": total_findings,
                          "severity_breakdown": severity_counts,
                          "critical_count": severity_counts.get("CRITICAL", 0),
                          "high_count": severity_counts.get("HIGH", 0),
                          "source": "inspector2"},
                api="inspector2:ListFindings", region=region))

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDeniedException", "ValidationException"):
                evidence_items.append(self.observe(
                    resource=f"arn:aws:inspector2:{region}::status",
                    property="InspectorEnabled", value=False, expected=True,
                    metadata={"note": "Inspector not enabled or not accessible", "source": "inspector2"},
                    api="inspector2:ListFindings", region=region))
            else:
                logger.warning(f"Inspector error: {e}")

        # If no evidence at all, note it
        if not evidence_items:
            evidence_items.append(self.observe(
                resource=f"arn:aws:ec2:{region}::fleet",
                property="VulnManagementEnabled", value=False, expected=True,
                metadata={"note": "No SSM managed instances and Inspector not enabled",
                          "recommendation": "Enable SSM Agent on EC2 instances and activate Inspector"},
                api="ssm:DescribeInstanceInformation,inspector2:ListFindings", region=region))

        return evidence_items


class VulnManagementEvaluator:
    domain = "infrastructure.compute.vulnerability_management"
    assertion = "Vulnerability management is active with no unpatched critical findings"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.INDETERMINATE, confidence=0.0,
                                    assessment="No vulnerability data collected.")

        caveats = []
        recommendations = []
        has_ssm = False
        has_inspector = False
        critical_vulns = 0
        non_compliant_patches = 0
        all_patch_compliant = True
        inspector_enabled = True

        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            meta = obs.get("metadata", {})
            prop = obs.get("property", "")
            source = meta.get("source", "")

            if prop == "PatchCompliant":
                has_ssm = True
                if not obs.get("value", False):
                    all_patch_compliant = False
                    nc = meta.get("patches_non_compliant", 0)
                    crit = meta.get("critical_missing", 0)
                    non_compliant_patches += nc
                    critical_vulns += crit
                    inst = meta.get("instance_id", "?")
                    caveats.append(f"Instance {inst}: {nc} non-compliant patches ({crit} critical)")

            elif prop == "NoActiveCriticalFindings":
                has_inspector = True
                if not obs.get("value", False):
                    c = meta.get("critical_count", 0)
                    critical_vulns += c
                    caveats.append(f"Inspector: {c} critical, {meta.get('high_count',0)} high active findings")

            elif prop == "InspectorEnabled":
                inspector_enabled = False
                caveats.append("Amazon Inspector is not enabled")
                recommendations.append("Enable Inspector for continuous vulnerability scanning")

            elif prop == "VulnManagementEnabled":
                caveats.append("No vulnerability management tools detected")
                recommendations.append("Enable SSM Agent on EC2 instances for patch management")
                recommendations.append("Activate Amazon Inspector for vulnerability scanning")
                return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=0.90,
                    assessment="No vulnerability management infrastructure detected.",
                    caveats=caveats, recommendations=recommendations,
                    evidence_ids=[e.evidence_id for e in evidence_items])

        if not has_ssm and not has_inspector:
            if not inspector_enabled:
                return EvaluationResult(result=ClaimResult.PARTIAL, confidence=0.5,
                    assessment="No EC2 instances under SSM management and Inspector not enabled.",
                    caveats=caveats, recommendations=recommendations,
                    evidence_ids=[e.evidence_id for e in evidence_items])

        if critical_vulns > 0:
            recommendations.append(f"Remediate {critical_vulns} critical vulnerability(ies) within 30 days")
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=0.95,
                assessment=f"Critical vulnerabilities found: {critical_vulns} critical finding(s) require immediate attention.",
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])

        if all_patch_compliant and inspector_enabled:
            conf = 0.90 if has_ssm and has_inspector else 0.80
            return EvaluationResult(result=ClaimResult.SATISFIED, confidence=conf,
                assessment=f"No critical vulnerabilities. {'Patch compliance verified. ' if has_ssm else ''}{'Inspector active. ' if has_inspector else ''}",
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])

        return EvaluationResult(result=ClaimResult.PARTIAL, confidence=0.6,
            assessment=f"Vulnerability management partially configured. {non_compliant_patches} non-compliant patches found.",
            caveats=caveats, recommendations=recommendations,
            evidence_ids=[e.evidence_id for e in evidence_items])


class AWSVulnAgent:
    def __init__(self, agent, region="us-east-2"):
        self.agent = agent; self.region = region
        self.collector = VulnManagementCollector()
        self.evaluator = VulnManagementEvaluator()

    @classmethod
    def create(cls, region="us-east-2"):
        keys = KeyPair.generate()
        config = __import__('otvp_agent').AgentConfig(agent_id="aws-vuln-agent-v1",
            vendor="OTVP Reference / Killswitch Advisory", version="1.0.0", key_pair=keys,
            domains=["infrastructure.compute.vulnerability_management"])
        return cls(agent=Agent(config), region=region)

    async def run(self, subject="killswitch-advisory", relying_party=None):
        ctx = CollectionContext(environment="test", region=self.region)
        print("=" * 70)
        print("  OTVP Reference Agent: Vulnerability Management")
        print(f"  Region: {self.region}")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        evidence = await self.collector.collect(ctx)
        print(f"  ✓ Collected {len(evidence)} vulnerability evidence items")
        print()

        signed_refs = [self.agent.sign_evidence(ev).evidence_id for ev in evidence]
        result = await self.evaluator.evaluate(evidence)

        print(f"  Evaluation: {result.result.value}")
        print(f"  Confidence: {result.confidence:.0%}")
        print(f"  Assessment: {result.assessment}")
        for c in result.caveats: print(f"  ⚠ Caveat: {c}")
        for r in result.recommendations: print(f"  → Recommendation: {r}")
        print()

        claim = self.agent.create_claim(
            domain=self.evaluator.domain, assertion=self.evaluator.assertion,
            result=result.result, confidence=result.confidence, evidence_refs=signed_refs,
            opinion=result.assessment, caveats=result.caveats, recommendations=result.recommendations,
            scope=ClaimScope(environment="test", services=["SSM", "Inspector"], regions=[self.region]))

        envelope = self.agent.build_envelope(claims=[claim], subject=subject, relying_party=relying_party)

        print("─" * 70)
        print(envelope.summary())
        print()
        print("─" * 70)
        print("Verification:")
        print(f"  Envelope signature valid: {self.agent.verify_envelope(envelope)}")
        for c in envelope.claims: print(f"  Claim [{c.claim_id}] signature valid: {self.agent.verify_claim(c)}")
        print(f"  Evidence store size: {self.agent.evidence_store.size}")
        print(f"  Merkle root: {self.agent.evidence_store.root_hash}")
        store = self.agent.evidence_store
        for i in range(min(3, store.size)):
            print(f"  Evidence [{i}] Merkle proof valid: {store.get_proof(i).verify()}")
        print()
        print("─" * 70)
        print("Full Trust Envelope (JSON):")
        print("─" * 70)
        print(envelope.to_json(indent=2))
        output_path = f"trust_envelope_vuln_{subject}.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  ✓ Envelope saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="OTVP AWS Vulnerability Management Agent")
    parser.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    agent = AWSVulnAgent.create(region=args.region)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
