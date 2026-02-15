#!/usr/bin/env python3
"""
OTVP Reference Agent: Audit Logging

Verifies CloudTrail configuration, VPC flow log coverage, and log integrity.

Maps to SOC 2 CC7.1, CC7.2 | ISO 27001 A.12.4.1 | NIST CSF DE.AE-3

Usage:
    export AWS_PROFILE=otvp-test
    export AWS_DEFAULT_REGION=us-east-2
    python run_logging_agent.py
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
from otvp_agent import Agent, AgentConfig, Domain, Evidence, EvidenceType, KeyPair
from otvp_agent.agents import Collector, CollectionContext, EvaluationResult
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.aws_logging")


class CloudTrailCollector(Collector):
    """Collects CloudTrail configuration evidence."""
    domain = "detection_and_response.logging.completeness"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        region = context.region or "us-east-2"
        ct = boto3.client("cloudtrail", region_name=region)
        evidence_items = []

        try:
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

            if not trails:
                evidence_items.append(
                    self.observe(
                        resource=f"arn:aws:cloudtrail:{region}::no-trail",
                        property="CloudTrailEnabled",
                        value=False,
                        expected=True,
                        metadata={"note": "No CloudTrail trails configured in this account"},
                        api="cloudtrail:DescribeTrails",
                        region=region,
                    )
                )
                return evidence_items

            for trail in trails:
                trail_name = trail.get("Name", "unknown")
                trail_arn = trail.get("TrailARN", "unknown")
                is_multi_region = trail.get("IsMultiRegionTrail", False)
                is_org_trail = trail.get("IsOrganizationTrail", False)
                log_validation = trail.get("LogFileValidationEnabled", False)
                s3_bucket = trail.get("S3BucketName", "none")
                kms_key = trail.get("KmsKeyId")
                has_cw_logs = trail.get("CloudWatchLogsLogGroupArn") is not None

                # Check trail status
                is_logging = False
                try:
                    status = ct.get_trail_status(Name=trail_arn)
                    is_logging = status.get("IsLogging", False)
                except ClientError as e:
                    logger.warning(f"Error getting trail status for {trail_name}: {e}")

                # Evaluate overall compliance
                is_compliant = all([
                    is_logging,
                    is_multi_region,
                    log_validation,
                ])

                evidence_items.append(
                    self.observe(
                        resource=trail_arn,
                        property="CloudTrailCompliant",
                        value=is_compliant,
                        expected=True,
                        metadata={
                            "trail_name": trail_name,
                            "is_logging": is_logging,
                            "is_multi_region": is_multi_region,
                            "is_organization_trail": is_org_trail,
                            "log_file_validation": log_validation,
                            "s3_bucket": s3_bucket,
                            "kms_encrypted": kms_key is not None,
                            "kms_key_id": kms_key,
                            "cloudwatch_logs_enabled": has_cw_logs,
                        },
                        api="cloudtrail:DescribeTrails,cloudtrail:GetTrailStatus",
                        region=region,
                    )
                )

        except ClientError as e:
            logger.error(f"Error describing trails: {e}")

        return evidence_items


class VPCFlowLogCollector(Collector):
    """Collects VPC flow log coverage evidence."""
    domain = "detection_and_response.logging.completeness"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        region = context.region or "us-east-2"
        ec2 = boto3.client("ec2", region_name=region)
        evidence_items = []

        try:
            # Get all VPCs
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            # Get all flow logs
            flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
            vpc_flow_log_map = {}
            for fl in flow_logs:
                resource_id = fl.get("ResourceId", "")
                if resource_id.startswith("vpc-"):
                    vpc_flow_log_map[resource_id] = fl

            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                is_default = vpc.get("IsDefault", False)
                vpc_name = "unnamed"
                for tag in vpc.get("Tags", []):
                    if tag["Key"] == "Name":
                        vpc_name = tag["Value"]

                has_flow_log = vpc_id in vpc_flow_log_map
                fl_info = vpc_flow_log_map.get(vpc_id, {})

                evidence_items.append(
                    self.observe(
                        resource=f"arn:aws:ec2:{region}::vpc/{vpc_id}",
                        property="FlowLogEnabled",
                        value=has_flow_log,
                        expected=True,
                        metadata={
                            "vpc_id": vpc_id,
                            "vpc_name": vpc_name,
                            "is_default": is_default,
                            "flow_log_status": fl_info.get("FlowLogStatus", "NOT_CONFIGURED"),
                            "traffic_type": fl_info.get("TrafficType", "N/A"),
                            "destination": fl_info.get("LogDestinationType", "N/A"),
                        },
                        api="ec2:DescribeVpcs,ec2:DescribeFlowLogs",
                        region=region,
                    )
                )

        except ClientError as e:
            logger.error(f"Error checking VPC flow logs: {e}")

        return evidence_items


class AuditLoggingEvaluator:
    """Evaluates audit logging posture across CloudTrail and VPC flow logs."""
    domain = "detection_and_response.logging.completeness"
    assertion = "Audit logging is enabled with multi-region CloudTrail and VPC flow logs on all VPCs"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(
                result=ClaimResult.INDETERMINATE,
                confidence=0.0,
                assessment="No logging evidence collected.",
            )

        trail_items = []
        vpc_items = []
        issues = []
        recommendations = []

        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            prop = obs.get("property", "")
            meta = obs.get("metadata", {})
            value = obs.get("value", False)

            if prop == "CloudTrailCompliant":
                trail_items.append(item)
                if not value:
                    trail_name = meta.get("trail_name", "unknown")
                    if not meta.get("is_logging"):
                        issues.append(f"CloudTrail '{trail_name}' is not actively logging")
                    if not meta.get("is_multi_region"):
                        issues.append(f"CloudTrail '{trail_name}' is not multi-region")
                    if not meta.get("log_file_validation"):
                        issues.append(f"CloudTrail '{trail_name}' has log file validation disabled")
                        recommendations.append(f"Enable log file validation on trail '{trail_name}'")
                    if not meta.get("kms_encrypted"):
                        recommendations.append(f"Enable KMS encryption on trail '{trail_name}' for log confidentiality")

            elif prop == "FlowLogEnabled":
                vpc_items.append(item)
                if not value:
                    vpc_id = meta.get("vpc_id", "unknown")
                    vpc_name = meta.get("vpc_name", "unnamed")
                    issues.append(f"VPC '{vpc_name}' ({vpc_id}) has no flow logs enabled")

        # Score
        total_checks = len(evidence_items)
        passing = sum(1 for e in evidence_items
                      if isinstance(e.observation, dict) and e.observation.get("value", False))
        pct = passing / total_checks if total_checks > 0 else 0

        trail_compliant = sum(1 for e in trail_items
                              if isinstance(e.observation, dict) and e.observation.get("value", False))
        vpc_covered = sum(1 for e in vpc_items
                          if isinstance(e.observation, dict) and e.observation.get("value", False))

        if not trail_items or trail_compliant == 0:
            issues.insert(0, "No compliant CloudTrail configuration found")
            recommendations.insert(0, "Create a multi-region CloudTrail with log file validation enabled")

        if vpc_items and vpc_covered == 0:
            recommendations.append("Enable VPC flow logs on all VPCs — send to CloudWatch Logs or S3")

        caveats = issues[:5]  # Cap display

        if pct == 1.0:
            conf = min(0.99, 0.85 + 0.14 * min(total_checks / 10, 1.0))
            return EvaluationResult(
                result=ClaimResult.SATISFIED,
                confidence=round(conf, 3),
                assessment=f"All logging checks passed. {trail_compliant} compliant trail(s), {vpc_covered}/{len(vpc_items)} VPC(s) with flow logs.",
                caveats=caveats,
                recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items],
            )
        elif pct > 0.5:
            return EvaluationResult(
                result=ClaimResult.PARTIAL,
                confidence=round(pct * 0.85, 3),
                assessment=f"{passing}/{total_checks} logging checks passed. {trail_compliant} compliant trail(s), {vpc_covered}/{len(vpc_items)} VPC(s) with flow logs.",
                caveats=caveats,
                recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items],
            )
        else:
            return EvaluationResult(
                result=ClaimResult.NOT_SATISFIED,
                confidence=0.95,
                assessment=f"Only {passing}/{total_checks} logging checks passed. Significant gaps in audit logging coverage.",
                caveats=caveats,
                recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items],
            )


class AWSLoggingAgent:
    def __init__(self, agent: Agent, region: str = "us-east-2") -> None:
        self.agent = agent
        self.region = region
        self.collectors = [CloudTrailCollector(), VPCFlowLogCollector()]
        self.evaluator = AuditLoggingEvaluator()

    @classmethod
    def create(cls, region: str = "us-east-2") -> AWSLoggingAgent:
        keys = KeyPair.generate()
        config = AgentConfig(
            agent_id="aws-logging-agent-v1",
            vendor="OTVP Reference / Killswitch Advisory",
            version="1.0.0",
            key_pair=keys,
            domains=[Domain.LOGGING_COMPLETENESS],
        )
        agent = Agent(config)
        return cls(agent=agent, region=region)

    async def run(self, subject: str = "killswitch-advisory",
                  relying_party: str | None = None) -> None:
        ctx = CollectionContext(environment="test", region=self.region)

        print("=" * 70)
        print("  OTVP Reference Agent: Audit Logging")
        print(f"  Region: {self.region}")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        all_evidence = []
        for collector in self.collectors:
            items = await collector.collect(ctx)
            all_evidence.extend(items)
            print(f"  ✓ Collected {len(items)} items from {collector.__class__.__name__}")
        print(f"\n  Total evidence: {len(all_evidence)}")
        print()

        signed_refs = []
        for ev in all_evidence:
            signed = self.agent.sign_evidence(ev)
            signed_refs.append(signed.evidence_id)

        result = await self.evaluator.evaluate(all_evidence)
        print(f"  Evaluation: {result.result.value}")
        print(f"  Confidence: {result.confidence:.0%}")
        print(f"  Assessment: {result.assessment}")
        if result.caveats:
            for c in result.caveats:
                print(f"  ⚠ Caveat: {c}")
        if result.recommendations:
            for r in result.recommendations:
                print(f"  → Recommendation: {r}")
        print()

        claim = self.agent.create_claim(
            domain="detection_and_response.logging.completeness",
            assertion=self.evaluator.assertion,
            result=result.result, confidence=result.confidence,
            evidence_refs=signed_refs, opinion=result.assessment,
            caveats=result.caveats, recommendations=result.recommendations,
            scope=ClaimScope(environment="test", services=["CloudTrail", "VPC FlowLogs"], regions=[self.region]),
        )

        envelope = self.agent.build_envelope(claims=[claim], subject=subject, relying_party=relying_party)

        print("─" * 70)
        print(envelope.summary())
        print()
        print("─" * 70)
        print("Verification:")
        print(f"  Envelope signature valid: {self.agent.verify_envelope(envelope)}")
        for c in envelope.claims:
            print(f"  Claim [{c.claim_id}] signature valid: {self.agent.verify_claim(c)}")
        print(f"  Evidence store size: {self.agent.evidence_store.size}")
        print(f"  Merkle root: {self.agent.evidence_store.root_hash}")
        print()
        store = self.agent.evidence_store
        for i in range(min(3, store.size)):
            proof = store.get_proof(i)
            print(f"  Evidence [{i}] Merkle proof valid: {proof.verify()}")
        print()
        print("─" * 70)
        print("Full Trust Envelope (JSON):")
        print("─" * 70)
        print(envelope.to_json(indent=2))

        output_path = f"trust_envelope_logging_{subject}.json"
        with open(output_path, "w") as f:
            f.write(envelope.to_json(indent=2))
        print(f"\n  ✓ Envelope saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="OTVP AWS Audit Logging Agent")
    parser.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    agent = AWSLoggingAgent.create(region=args.region)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))


if __name__ == "__main__":
    main()
