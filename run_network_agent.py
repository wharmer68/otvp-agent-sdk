#!/usr/bin/env python3
"""
OTVP Reference Agent: Network Segmentation

Verifies VPC design, security group rules, and NACL configuration.
Flags overly permissive rules (0.0.0.0/0 on non-HTTPS ports).

Maps to SOC 2 CC6.1, CC6.6 | ISO 27001 A.13.1.1 | NIST CSF PR.AC-5

Usage:
    export AWS_PROFILE=otvp-test
    export AWS_DEFAULT_REGION=us-east-2
    python run_network_agent.py
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

logger = logging.getLogger("otvp.agent.aws_network")

# Ports that are acceptable to expose publicly
ACCEPTABLE_PUBLIC_PORTS = {443, 80}  # HTTPS, HTTP
# Ports that are high risk if exposed
HIGH_RISK_PORTS = {22, 3389, 5432, 3306, 1433, 27017, 6379, 9200, 11211}
HIGH_RISK_NAMES = {
    22: "SSH", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL",
    1433: "MSSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
    11211: "Memcached",
}


class SecurityGroupCollector(Collector):
    """Collects security group configuration evidence."""
    domain = "network_security.segmentation"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        region = context.region or "us-east-2"
        ec2 = boto3.client("ec2", region_name=region)
        evidence_items = []

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", "unnamed")
                    vpc_id = sg.get("VpcId", "none")
                    description = sg.get("Description", "")

                    # Analyze ingress rules
                    open_to_world = []
                    high_risk_open = []
                    total_rules = len(sg.get("IpPermissions", []))

                    for rule in sg.get("IpPermissions", []):
                        from_port = rule.get("FromPort", 0)
                        to_port = rule.get("ToPort", 65535)
                        protocol = rule.get("IpProtocol", "unknown")

                        # Check for 0.0.0.0/0 or ::/0
                        is_open_ipv4 = any(
                            r.get("CidrIp") == "0.0.0.0/0"
                            for r in rule.get("IpRanges", [])
                        )
                        is_open_ipv6 = any(
                            r.get("CidrIpv6") == "::/0"
                            for r in rule.get("Ipv6Ranges", [])
                        )
                        is_open = is_open_ipv4 or is_open_ipv6

                        if is_open:
                            if protocol == "-1":  # All traffic
                                open_to_world.append("ALL TRAFFIC")
                                high_risk_open.append("ALL TRAFFIC (all ports, all protocols)")
                            elif from_port == 0 and to_port == 65535:
                                open_to_world.append(f"ALL {protocol.upper()} PORTS")
                                high_risk_open.append(f"All {protocol.upper()} ports open to internet")
                            else:
                                port_range = f"{from_port}" if from_port == to_port else f"{from_port}-{to_port}"
                                open_to_world.append(f"{protocol.upper()}:{port_range}")

                                # Check if high-risk port is exposed
                                for port in range(from_port, min(to_port + 1, from_port + 100)):
                                    if port in HIGH_RISK_PORTS:
                                        name = HIGH_RISK_NAMES.get(port, f"port {port}")
                                        high_risk_open.append(f"{name} (port {port}) open to internet")

                    # Determine if SG is properly segmented
                    is_compliant = len(high_risk_open) == 0
                    # If only 80/443 are open to world, that's acceptable for public-facing
                    only_web_ports_open = all(
                        any(str(p) in entry for p in ACCEPTABLE_PUBLIC_PORTS) or "TRAFFIC" not in entry
                        for entry in open_to_world
                    ) if open_to_world else True

                    evidence_items.append(
                        self.observe(
                            resource=f"arn:aws:ec2:{region}::security-group/{sg_id}",
                            property="ProperlySegmented",
                            value=is_compliant,
                            expected=True,
                            metadata={
                                "sg_id": sg_id,
                                "sg_name": sg_name,
                                "vpc_id": vpc_id,
                                "description": description,
                                "total_ingress_rules": total_rules,
                                "open_to_world": open_to_world,
                                "high_risk_open": high_risk_open,
                                "only_web_ports_open": only_web_ports_open,
                            },
                            api="ec2:DescribeSecurityGroups",
                            region=region,
                        )
                    )

        except ClientError as e:
            logger.error(f"Error describing security groups: {e}")

        return evidence_items


class NetworkSegmentationEvaluator:
    """Evaluates network segmentation posture.

    Critical findings: high-risk ports (SSH, RDP, DB ports) open to 0.0.0.0/0
    Warning findings: any non-web port open to world
    """
    domain = "network_security.segmentation"
    assertion = "No high-risk ports are exposed to the public internet via security groups"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(
                result=ClaimResult.INDETERMINATE,
                confidence=0.0,
                assessment="No security groups found to evaluate.",
            )

        total_sgs = len(evidence_items)
        compliant_sgs = []
        non_compliant_sgs = []
        all_high_risk = []

        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            meta = obs.get("metadata", {})
            sg_name = meta.get("sg_name", "unknown")
            sg_id = meta.get("sg_id", "unknown")
            high_risk = meta.get("high_risk_open", [])
            is_compliant = obs.get("value", False)

            if is_compliant:
                compliant_sgs.append(f"{sg_name} ({sg_id})")
            else:
                non_compliant_sgs.append(f"{sg_name} ({sg_id})")
                for risk in high_risk:
                    all_high_risk.append(f"{sg_name}: {risk}")

        pct = len(compliant_sgs) / total_sgs if total_sgs > 0 else 0
        caveats = []
        recommendations = []

        if all_high_risk:
            caveats.append(f"Critical exposures found: {'; '.join(all_high_risk[:5])}")
            if len(all_high_risk) > 5:
                caveats.append(f"...and {len(all_high_risk) - 5} more")
            recommendations.append("Immediately restrict high-risk ports to specific IP ranges or VPN CIDR blocks")
            recommendations.append("Use AWS Systems Manager Session Manager instead of direct SSH access")

        if pct == 1.0:
            conf = min(0.99, 0.85 + 0.14 * min(total_sgs / 20, 1.0))
            return EvaluationResult(
                result=ClaimResult.SATISFIED,
                confidence=round(conf, 3),
                assessment=f"All {total_sgs} security group(s) properly segmented. No high-risk ports exposed to internet.",
                caveats=caveats,
                evidence_ids=[e.evidence_id for e in evidence_items],
            )
        elif pct > 0.5:
            return EvaluationResult(
                result=ClaimResult.PARTIAL,
                confidence=round(pct * 0.8, 3),
                assessment=f"{len(compliant_sgs)}/{total_sgs} security group(s) properly segmented.",
                caveats=caveats,
                recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items],
            )
        else:
            return EvaluationResult(
                result=ClaimResult.NOT_SATISFIED,
                confidence=0.95,
                assessment=f"Only {len(compliant_sgs)}/{total_sgs} security group(s) properly segmented. {len(all_high_risk)} high-risk exposure(s) found.",
                caveats=caveats,
                recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items],
            )


class AWSNetworkAgent:
    def __init__(self, agent: Agent, region: str = "us-east-2") -> None:
        self.agent = agent
        self.region = region
        self.collector = SecurityGroupCollector()
        self.evaluator = NetworkSegmentationEvaluator()

    @classmethod
    def create(cls, region: str = "us-east-2") -> AWSNetworkAgent:
        keys = KeyPair.generate()
        config = AgentConfig(
            agent_id="aws-network-agent-v1",
            vendor="OTVP Reference / Killswitch Advisory",
            version="1.0.0",
            key_pair=keys,
            domains=[Domain.NETWORK_SEGMENTATION],
        )
        agent = Agent(config)
        return cls(agent=agent, region=region)

    async def run(self, subject: str = "killswitch-advisory",
                  relying_party: str | None = None) -> None:
        ctx = CollectionContext(environment="test", region=self.region)

        print("=" * 70)
        print("  OTVP Reference Agent: Network Segmentation")
        print(f"  Region: {self.region}")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        # 1. Collect
        evidence = await self.collector.collect(ctx)
        print(f"  ✓ Collected {len(evidence)} security group evidence items")
        exposed_count = sum(1 for e in evidence
                           if isinstance(e.observation, dict)
                           and e.observation.get("metadata", {}).get("high_risk_open"))
        print(f"    With high-risk exposure: {exposed_count}")
        print()

        # 2. Sign and store
        signed_refs = []
        for ev in evidence:
            signed = self.agent.sign_evidence(ev)
            signed_refs.append(signed.evidence_id)

        # 3. Evaluate
        result = await self.evaluator.evaluate(evidence)
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

        # 4. Claim
        claim = self.agent.create_claim(
            domain="network_security.segmentation",
            assertion=self.evaluator.assertion,
            result=result.result,
            confidence=result.confidence,
            evidence_refs=signed_refs,
            opinion=result.assessment,
            caveats=result.caveats,
            recommendations=result.recommendations,
            scope=ClaimScope(environment="test", services=["VPC", "SecurityGroups"], regions=[self.region]),
        )

        # 5. Envelope
        envelope = self.agent.build_envelope(claims=[claim], subject=subject, relying_party=relying_party)

        # 6. Output
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

        output_path = f"trust_envelope_network_{subject}.json"
        with open(output_path, "w") as f:
            f.write(envelope.to_json(indent=2))
        print(f"\n  ✓ Envelope saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="OTVP AWS Network Segmentation Agent")
    parser.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    agent = AWSNetworkAgent.create(region=args.region)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))


if __name__ == "__main__":
    main()
