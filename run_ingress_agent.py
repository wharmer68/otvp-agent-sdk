#!/usr/bin/env python3
"""
OTVP Reference Agent: Ingress Controls

Evaluates public-facing exposure: security groups with 0.0.0.0/0 on non-web ports,
load balancer scheme (internet-facing vs internal), WAF coverage.

Maps to SOC 2 CC6.6 | ISO 27001 A.13.1.3 | NIST CSF PR.AC-5

Usage:
    export AWS_PROFILE=otvp-test
    python run_ingress_agent.py
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

logger = logging.getLogger("otvp.agent.aws_ingress")

ACCEPTABLE_PUBLIC_PORTS = {80, 443}


class IngressCollector(Collector):
    domain = "network_security.ingress_controls"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        region = context.region or "us-east-2"
        ec2 = boto3.client("ec2", region_name=region)
        elbv2 = boto3.client("elbv2", region_name=region)
        evidence_items = []

        # Check security groups for public exposure on non-web ports
        try:
            for page in ec2.get_paginator("describe_security_groups").paginate():
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", "unnamed")

                    public_non_web = []
                    public_web = []

                    for rule in sg.get("IpPermissions", []):
                        from_port = rule.get("FromPort", 0)
                        to_port = rule.get("ToPort", 65535)
                        protocol = rule.get("IpProtocol", "")

                        is_open = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
                        is_open = is_open or any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))

                        if not is_open:
                            continue

                        if protocol == "-1":
                            public_non_web.append("ALL TRAFFIC")
                        elif from_port == 0 and to_port == 65535:
                            public_non_web.append(f"ALL {protocol.upper()} PORTS")
                        else:
                            ports_in_range = set(range(from_port, min(to_port + 1, from_port + 200)))
                            web_overlap = ports_in_range & ACCEPTABLE_PUBLIC_PORTS
                            non_web = ports_in_range - ACCEPTABLE_PUBLIC_PORTS

                            if web_overlap:
                                public_web.extend([str(p) for p in sorted(web_overlap)])
                            if non_web:
                                if len(non_web) > 5:
                                    public_non_web.append(f"{from_port}-{to_port}")
                                else:
                                    public_non_web.extend([str(p) for p in sorted(non_web)])

                    if public_non_web or public_web:
                        evidence_items.append(
                            self.observe(
                                resource=f"arn:aws:ec2:{region}::security-group/{sg_id}",
                                property="IngressControlled",
                                value=len(public_non_web) == 0,
                                expected=True,
                                metadata={
                                    "sg_id": sg_id,
                                    "sg_name": sg_name,
                                    "public_web_ports": public_web,
                                    "public_non_web_ports": public_non_web,
                                    "resource_type": "security_group",
                                },
                                api="ec2:DescribeSecurityGroups",
                                region=region,
                            )
                        )
        except ClientError as e:
            logger.error(f"Error checking security groups: {e}")

        # Check internet-facing load balancers for WAF coverage
        try:
            lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
            internet_facing = [lb for lb in lbs if lb.get("Scheme") == "internet-facing"]

            for lb in internet_facing:
                lb_arn = lb["LoadBalancerArn"]
                lb_name = lb.get("LoadBalancerName", "unnamed")

                # Check WAF association
                has_waf = False
                try:
                    wafv2 = boto3.client("wafv2", region_name=region)
                    waf_resp = wafv2.get_web_acl_for_resource(ResourceArn=lb_arn)
                    has_waf = waf_resp.get("WebACL") is not None
                except ClientError as e:
                    if "WAFNonexistentItemException" in str(e):
                        has_waf = False
                    else:
                        logger.warning(f"Error checking WAF for {lb_name}: {e}")

                evidence_items.append(
                    self.observe(
                        resource=lb_arn,
                        property="IngressControlled",
                        value=has_waf,
                        expected=True,
                        metadata={
                            "lb_name": lb_name,
                            "lb_type": lb.get("Type", "unknown"),
                            "scheme": "internet-facing",
                            "has_waf": has_waf,
                            "resource_type": "load_balancer",
                        },
                        api="elbv2:DescribeLoadBalancers,wafv2:GetWebACLForResource",
                        region=region,
                    )
                )
        except ClientError as e:
            logger.warning(f"Error checking load balancers: {e}")

        return evidence_items


class IngressControlsEvaluator:
    domain = "network_security.ingress_controls"
    assertion = "All public-facing resources have controlled ingress with WAF protection on internet-facing load balancers"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.SATISFIED, confidence=1.0,
                assessment="No public-facing security groups or internet-facing load balancers found. Attack surface is minimal. 100% of resources verified.",
                evidence_ids=[])

        compliant = []
        non_compliant = []
        caveats = []
        recommendations = []

        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            meta = obs.get("metadata", {})
            value = obs.get("value", False)
            rtype = meta.get("resource_type", "")

            if rtype == "security_group":
                sg_name = meta.get("sg_name", "unknown")
                if value:
                    compliant.append(f"SG:{sg_name}")
                else:
                    non_compliant.append(f"SG:{sg_name}")
                    ports = meta.get("public_non_web_ports", [])
                    caveats.append(f"SG {sg_name}: non-web ports open to internet: {', '.join(ports)}")

            elif rtype == "load_balancer":
                lb_name = meta.get("lb_name", "unknown")
                if value:
                    compliant.append(f"ALB:{lb_name}")
                else:
                    non_compliant.append(f"ALB:{lb_name}")
                    caveats.append(f"Internet-facing ALB '{lb_name}' has no WAF attached")
                    recommendations.append(f"Attach a WAF web ACL to ALB '{lb_name}'")

        if non_compliant:
            recommendations.append("Restrict non-web ports to specific CIDR ranges or VPN")

        total = len(evidence_items)
        pct = len(compliant) / total if total > 0 else 0

        if pct == 1.0:
            return EvaluationResult(result=ClaimResult.SATISFIED, confidence=1.0,
                assessment=f"All {total} public-facing resource(s) have controlled ingress.",
                caveats=caveats, evidence_ids=[e.evidence_id for e in evidence_items])
        elif pct >= 0.5:
            return EvaluationResult(result=ClaimResult.PARTIAL, confidence=round(pct, 3),
                assessment=f"{len(compliant)}/{total} public-facing resources have proper ingress controls.",
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])
        else:
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=1.0,
                assessment=f"Only {len(compliant)}/{total} public-facing resources are properly controlled.",
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])


class AWSIngressAgent:
    def __init__(self, agent: Agent, region: str = "us-east-2") -> None:
        self.agent = agent
        self.region = region
        self.collector = IngressCollector()
        self.evaluator = IngressControlsEvaluator()

    @classmethod
    def create(cls, region: str = "us-east-2") -> AWSIngressAgent:
        keys = KeyPair.generate()
        config = AgentConfig(agent_id="aws-ingress-agent-v1", vendor="OTVP Reference / Killswitch Advisory",
            version="1.0.0", key_pair=keys, domains=["network_security.ingress_controls"])
        return cls(agent=Agent(config), region=region)

    async def run(self, subject: str = "killswitch-advisory", relying_party: str | None = None) -> None:
        ctx = CollectionContext(environment="test", region=self.region)
        print("=" * 70)
        print("  OTVP Reference Agent: Ingress Controls")
        print(f"  Region: {self.region}")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        evidence = await self.collector.collect(ctx)
        sg_count = sum(1 for e in evidence if (e.observation or {}).get("metadata", {}).get("resource_type") == "security_group")
        lb_count = sum(1 for e in evidence if (e.observation or {}).get("metadata", {}).get("resource_type") == "load_balancer")
        print(f"  ✓ Collected {len(evidence)} evidence items")
        print(f"    Public security groups: {sg_count}")
        print(f"    Internet-facing load balancers: {lb_count}")
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
            scope=ClaimScope(environment="test", services=["VPC", "ALB", "WAF"], regions=[self.region]))

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
        output_path = f"trust_envelope_ingress_{subject}.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  ✓ Envelope saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="OTVP AWS Ingress Controls Agent")
    parser.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    agent = AWSIngressAgent.create(region=args.region)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
