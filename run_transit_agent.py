#!/usr/bin/env python3
"""
OTVP Reference Agent: Encryption in Transit

Verifies TLS configuration on load balancers and checks certificate validity.
Maps to SOC 2 CC6.1, CC6.7 | ISO 27001 A.13.1.1 | NIST CSF PR.DS-2

Usage:
    export AWS_PROFILE=otvp-test
    python run_transit_agent.py
"""
from __future__ import annotations

import asyncio
import argparse
import logging
import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import boto3
from botocore.exceptions import ClientError
from otvp_agent import Agent, AgentConfig, Domain, Evidence, EvidenceType, KeyPair
from otvp_agent.agents import Collector, CollectionContext, EvaluationResult
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.aws_transit")

MINIMUM_TLS = "TLSv1.2"
CERT_EXPIRY_WARNING_DAYS = 30
WEAK_POLICIES = {"ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS-1-0-2015-04", "ELBSecurityPolicy-TLS-1-1-2017-01"}


class ALBTLSCollector(Collector):
    domain = "data_protection.encryption.in_transit"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        region = context.region or "us-east-2"
        elbv2 = boto3.client("elbv2", region_name=region)
        acm = boto3.client("acm", region_name=region)
        evidence_items = []

        try:
            paginator = elbv2.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page["LoadBalancers"]:
                    lb_arn = lb["LoadBalancerArn"]
                    lb_name = lb.get("LoadBalancerName", "unnamed")
                    lb_type = lb.get("Type", "unknown")
                    lb_scheme = lb.get("Scheme", "unknown")

                    # Get listeners
                    try:
                        listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                    except ClientError as e:
                        logger.warning(f"Error describing listeners for {lb_name}: {e}")
                        continue

                    has_https = False
                    has_http_redirect = False
                    weak_tls = []
                    certs_expiring = []

                    for listener in listeners:
                        protocol = listener.get("Protocol", "")
                        port = listener.get("Port", 0)
                        ssl_policy = listener.get("SslPolicy")

                        if protocol == "HTTPS" or protocol == "TLS":
                            has_https = True
                            if ssl_policy and ssl_policy in WEAK_POLICIES:
                                weak_tls.append(f"port {port}: {ssl_policy}")

                            # Check certificates
                            for cert in listener.get("Certificates", []):
                                cert_arn = cert.get("CertificateArn", "")
                                if cert_arn.startswith("arn:aws:acm:"):
                                    try:
                                        cert_info = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
                                        not_after = cert_info.get("NotAfter")
                                        if not_after:
                                            days_left = (not_after.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                                            if days_left < CERT_EXPIRY_WARNING_DAYS:
                                                certs_expiring.append(f"{cert_info.get('DomainName','?')} expires in {days_left}d")
                                    except ClientError:
                                        pass

                        elif protocol == "HTTP":
                            actions = listener.get("DefaultActions", [])
                            for action in actions:
                                if action.get("Type") == "redirect":
                                    redirect = action.get("RedirectConfig", {})
                                    if redirect.get("Protocol") == "HTTPS":
                                        has_http_redirect = True

                    is_compliant = True
                    issues = []
                    if listeners and not has_https and lb_type != "network":
                        is_compliant = False
                        issues.append("No HTTPS listener configured")
                    if weak_tls:
                        is_compliant = False
                        issues.extend([f"Weak TLS policy on {w}" for w in weak_tls])
                    if certs_expiring:
                        issues.extend([f"Certificate expiring: {c}" for c in certs_expiring])

                    evidence_items.append(
                        self.observe(
                            resource=lb_arn,
                            property="TLSCompliant",
                            value=is_compliant,
                            expected=True,
                            metadata={
                                "lb_name": lb_name,
                                "lb_type": lb_type,
                                "scheme": lb_scheme,
                                "listener_count": len(listeners),
                                "has_https": has_https,
                                "has_http_redirect": has_http_redirect,
                                "weak_tls_policies": weak_tls,
                                "expiring_certificates": certs_expiring,
                                "issues": issues,
                            },
                            api="elbv2:DescribeLoadBalancers,elbv2:DescribeListeners,acm:DescribeCertificate",
                            region=region,
                        )
                    )

        except ClientError as e:
            logger.error(f"Error listing load balancers: {e}")

        # Also check ACM certificates independently for expiring certs
        try:
            certs = acm.list_certificates(CertificateStatuses=["ISSUED"]).get("CertificateSummaryList", [])
            for cert_summary in certs:
                cert_arn = cert_summary["CertificateArn"]
                domain = cert_summary.get("DomainName", "unknown")
                try:
                    cert_detail = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
                    not_after = cert_detail.get("NotAfter")
                    in_use = len(cert_detail.get("InUseBy", [])) > 0
                    days_left = (not_after.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days if not_after else None

                    evidence_items.append(
                        self.observe(
                            resource=cert_arn,
                            property="CertificateValid",
                            value=days_left is not None and days_left > CERT_EXPIRY_WARNING_DAYS,
                            expected=True,
                            metadata={
                                "domain": domain,
                                "days_until_expiry": days_left,
                                "in_use": in_use,
                                "status": cert_detail.get("Status"),
                                "type": cert_detail.get("Type"),
                            },
                            api="acm:ListCertificates,acm:DescribeCertificate",
                            region=region,
                        )
                    )
                except ClientError:
                    pass
        except ClientError as e:
            logger.warning(f"Error listing certificates: {e}")

        return evidence_items


class TransitEncryptionEvaluator:
    domain = "data_protection.encryption.in_transit"
    assertion = "All load balancers enforce TLS 1.2+ and certificates are valid"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.NOT_APPLICABLE, confidence=0.85,
                assessment="No load balancers or certificates found. Transit encryption evaluation not applicable.",
                evidence_ids=[])

        compliant = []
        non_compliant = []
        caveats = []
        recommendations = []

        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            meta = obs.get("metadata", {})
            value = obs.get("value", False)
            prop = obs.get("property", "")

            if prop == "TLSCompliant":
                name = meta.get("lb_name", "unknown")
                if value:
                    compliant.append(name)
                else:
                    non_compliant.append(name)
                    for issue in meta.get("issues", []):
                        caveats.append(f"{name}: {issue}")
            elif prop == "CertificateValid":
                domain = meta.get("domain", "unknown")
                days = meta.get("days_until_expiry")
                if not value and days is not None:
                    caveats.append(f"Certificate {domain} expires in {days} days")
                    recommendations.append(f"Renew certificate for {domain}")

        if non_compliant:
            recommendations.append("Upgrade TLS policies to ELBSecurityPolicy-TLS13-1-2-2021-06 or newer")
            recommendations.append("Ensure all HTTP listeners redirect to HTTPS")

        total = len([e for e in evidence_items if (e.observation or {}).get("property") == "TLSCompliant"])
        if total == 0:
            return EvaluationResult(result=ClaimResult.NOT_APPLICABLE, confidence=0.85,
                assessment="No load balancers found. Transit encryption at the load balancer layer not applicable.",
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])

        pct = len(compliant) / total if total > 0 else 0

        if pct == 1.0 and not caveats:
            return EvaluationResult(result=ClaimResult.SATISFIED, confidence=round(min(0.99, 0.85 + 0.14 * min(total/5, 1.0)), 3),
                assessment=f"All {total} load balancer(s) enforce TLS 1.2+. All certificates valid.",
                caveats=caveats, evidence_ids=[e.evidence_id for e in evidence_items])
        elif pct >= 0.5:
            return EvaluationResult(result=ClaimResult.PARTIAL, confidence=round(pct * 0.85, 3),
                assessment=f"{len(compliant)}/{total} load balancer(s) have compliant TLS configuration.",
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])
        else:
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=0.95,
                assessment=f"Only {len(compliant)}/{total} load balancer(s) have compliant TLS.",
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])


class AWSTransitAgent:
    def __init__(self, agent: Agent, region: str = "us-east-2") -> None:
        self.agent = agent
        self.region = region
        self.collector = ALBTLSCollector()
        self.evaluator = TransitEncryptionEvaluator()

    @classmethod
    def create(cls, region: str = "us-east-2") -> AWSTransitAgent:
        keys = KeyPair.generate()
        config = AgentConfig(agent_id="aws-transit-agent-v1", vendor="OTVP Reference / Killswitch Advisory",
            version="1.0.0", key_pair=keys, domains=[Domain.ENCRYPTION_IN_TRANSIT])
        return cls(agent=Agent(config), region=region)

    async def run(self, subject: str = "killswitch-advisory", relying_party: str | None = None) -> None:
        ctx = CollectionContext(environment="test", region=self.region)
        print("=" * 70)
        print("  OTVP Reference Agent: Encryption in Transit")
        print(f"  Region: {self.region}")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        evidence = await self.collector.collect(ctx)
        lb_count = sum(1 for e in evidence if (e.observation or {}).get("property") == "TLSCompliant")
        cert_count = sum(1 for e in evidence if (e.observation or {}).get("property") == "CertificateValid")
        print(f"  ✓ Collected {len(evidence)} evidence items")
        print(f"    Load balancers: {lb_count}")
        print(f"    Certificates: {cert_count}")
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
            scope=ClaimScope(environment="test", services=["ALB", "NLB", "ACM"], regions=[self.region]))

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
        output_path = f"trust_envelope_transit_{subject}.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  ✓ Envelope saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="OTVP AWS Encryption in Transit Agent")
    parser.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    agent = AWSTransitAgent.create(region=args.region)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
