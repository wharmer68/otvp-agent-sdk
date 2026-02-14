#!/usr/bin/env python3
"""
OTVP Reference Agent: IAM MFA Enforcement

Scans AWS IAM users with console access and verifies MFA is enabled.
Maps to SOC 2 CC6.1, ISO 27001 A.9.4.2, NIST CSF PR.AC-7, HIPAA §164.312(d).

Usage:
    export AWS_PROFILE=otvp-test
    export AWS_DEFAULT_REGION=us-east-2
    python run_mfa_agent.py
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
from otvp_agent.agents import BooleanEvaluator, Collector, CollectionContext, EvaluationResult
from otvp_agent.claims import ClaimResult, ClaimScope, Opinion

logger = logging.getLogger("otvp.agent.aws_mfa")


# ── Collectors ──────────────────────────────────────────────────────


class IAMMFACollector(Collector):
    """Collects MFA status for all IAM users with console access."""
    domain = "identity_and_access.authentication.mfa_enforcement"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        region = context.region or "us-east-2"
        iam = boto3.client("iam", region_name=region)
        evidence_items = []

        # Get all users
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                user_arn = user["Arn"]
                create_date = user["CreateDate"].isoformat()

                # Check if user has console access (login profile)
                has_console = False
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchEntity":
                        has_console = False
                    else:
                        logger.warning(f"Error checking login profile for {username}: {e}")
                        continue

                # Check MFA devices
                mfa_devices = []
                try:
                    mfa_response = iam.list_mfa_devices(UserName=username)
                    mfa_devices = mfa_response.get("MFADevices", [])
                except ClientError as e:
                    logger.warning(f"Error listing MFA for {username}: {e}")

                has_mfa = len(mfa_devices) > 0
                mfa_types = []
                for device in mfa_devices:
                    serial = device.get("SerialNumber", "")
                    if "mfa/totp" in serial or serial.startswith("arn:aws:iam::"):
                        mfa_types.append("virtual")
                    elif "sms" in serial:
                        mfa_types.append("sms")
                    else:
                        mfa_types.append("hardware" if "hardware" not in serial else "virtual")

                # Only report on users with console access
                # Programmatic-only users (API keys, no console) don't need MFA
                # in the same way — that's a different control
                if has_console:
                    evidence_items.append(
                        self.observe(
                            resource=user_arn,
                            property="MFAEnabled",
                            value=has_mfa,
                            expected=True,
                            metadata={
                                "username": username,
                                "has_console_access": has_console,
                                "mfa_device_count": len(mfa_devices),
                                "mfa_types": mfa_types,
                                "user_created": create_date,
                                "path": user.get("Path", "/"),
                            },
                            api="iam:ListUsers,iam:GetLoginProfile,iam:ListMFADevices",
                            region="global",  # IAM is global
                        )
                    )
                else:
                    # Still collect evidence for programmatic users, but note
                    # they're not in scope for console MFA enforcement
                    evidence_items.append(
                        self.observe(
                            resource=user_arn,
                            property="MFAEnabled",
                            value=has_mfa,
                            expected=None,  # No expectation for programmatic-only users
                            metadata={
                                "username": username,
                                "has_console_access": False,
                                "mfa_device_count": len(mfa_devices),
                                "note": "Programmatic-only user — MFA not required for console",
                                "user_created": create_date,
                            },
                            api="iam:ListUsers,iam:GetLoginProfile,iam:ListMFADevices",
                            region="global",
                        )
                    )

        return evidence_items


# ── Evaluator ───────────────────────────────────────────────────────


class MFAEnforcementEvaluator:
    """Evaluates whether all console users have MFA enabled.
    
    More nuanced than BooleanEvaluator — separates console users
    from programmatic-only users and evaluates them differently.
    """
    domain = "identity_and_access.authentication.mfa_enforcement"
    assertion = "All IAM users with console access have MFA enabled"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(
                result=ClaimResult.INDETERMINATE,
                confidence=0.0,
                assessment="No IAM users found to evaluate.",
            )

        console_users = []
        programmatic_users = []
        console_with_mfa = []
        console_without_mfa = []

        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            meta = obs.get("metadata", {})
            has_console = meta.get("has_console_access", False)
            has_mfa = obs.get("value", False)
            username = meta.get("username", "unknown")
            resource = obs.get("resource", "unknown")

            if has_console:
                console_users.append(username)
                if has_mfa:
                    console_with_mfa.append(username)
                else:
                    console_without_mfa.append(username)
            else:
                programmatic_users.append(username)

        total_console = len(console_users)
        total_programmatic = len(programmatic_users)

        if total_console == 0:
            return EvaluationResult(
                result=ClaimResult.NOT_APPLICABLE,
                confidence=0.90,
                assessment=f"No IAM users with console access found. {total_programmatic} programmatic-only user(s) present.",
                evidence_ids=[e.evidence_id for e in evidence_items],
            )

        pct = len(console_with_mfa) / total_console

        if pct == 1.0:
            conf = min(0.99, 0.85 + 0.14 * min(total_console / 10, 1.0))
            return EvaluationResult(
                result=ClaimResult.SATISFIED,
                confidence=round(conf, 3),
                assessment=f"All {total_console} console user(s) have MFA enabled. {total_programmatic} programmatic-only user(s) not in scope.",
                evidence_ids=[e.evidence_id for e in evidence_items],
            )
        elif pct > 0:
            caveats = [
                f"Console users WITHOUT MFA: {', '.join(console_without_mfa)}",
            ]
            if total_programmatic > 0:
                caveats.append(f"{total_programmatic} programmatic-only user(s) excluded from console MFA scope")
            return EvaluationResult(
                result=ClaimResult.PARTIAL,
                confidence=round(pct * 0.85, 3),
                assessment=f"{len(console_with_mfa)}/{total_console} console user(s) have MFA enabled.",
                caveats=caveats,
                recommendations=[
                    f"Enable MFA for: {', '.join(console_without_mfa)}",
                    "Consider enforcing MFA via IAM policy (aws:MultiFactorAuthPresent condition key)",
                ],
                evidence_ids=[e.evidence_id for e in evidence_items],
            )
        else:
            return EvaluationResult(
                result=ClaimResult.NOT_SATISFIED,
                confidence=0.95,
                assessment=f"No console users have MFA enabled (0/{total_console}).",
                caveats=[f"Users without MFA: {', '.join(console_without_mfa)}"],
                recommendations=[
                    "Enable MFA for all console users immediately",
                    "Deploy IAM policy requiring MFA for all API actions",
                    "Consider using AWS SSO with enforced MFA instead of IAM users",
                ],
                evidence_ids=[e.evidence_id for e in evidence_items],
            )


# ── Composite Agent ─────────────────────────────────────────────────


class AWSMFAAgent:
    def __init__(self, agent: Agent, region: str = "us-east-2") -> None:
        self.agent = agent
        self.region = region
        self.collector = IAMMFACollector()
        self.evaluator = MFAEnforcementEvaluator()

    @classmethod
    def create(cls, region: str = "us-east-2") -> AWSMFAAgent:
        keys = KeyPair.generate()
        config = AgentConfig(
            agent_id="aws-mfa-agent-v1",
            vendor="OTVP Reference / Killswitch Advisory",
            version="1.0.0",
            key_pair=keys,
            domains=[Domain.AUTHENTICATION_MFA],
        )
        agent = Agent(config)
        return cls(agent=agent, region=region)

    async def run(self, subject: str = "killswitch-advisory",
                  relying_party: str | None = None) -> None:
        ctx = CollectionContext(environment="test", region=self.region)

        print("=" * 70)
        print("  OTVP Reference Agent: IAM MFA Enforcement")
        print(f"  Region: global (IAM is not regional)")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        # 1. Collect
        evidence = await self.collector.collect(ctx)
        print(f"  ✓ Collected {len(evidence)} IAM user evidence items")

        # Summarize what we found
        console_count = 0
        prog_count = 0
        for ev in evidence:
            meta = ev.observation.get("metadata", {}) if isinstance(ev.observation, dict) else {}
            if meta.get("has_console_access"):
                console_count += 1
            else:
                prog_count += 1
        print(f"    Console users: {console_count}")
        print(f"    Programmatic-only users: {prog_count}")
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

        # 4. Create signed claim
        claim = self.agent.create_claim(
            domain="identity_and_access.authentication.mfa_enforcement",
            assertion=self.evaluator.assertion,
            result=result.result,
            confidence=result.confidence,
            evidence_refs=signed_refs,
            opinion=result.assessment,
            caveats=result.caveats,
            recommendations=result.recommendations,
            scope=ClaimScope(
                environment="test",
                services=["IAM"],
                regions=["global"],
            ),
        )

        # 5. Build envelope
        envelope = self.agent.build_envelope(
            claims=[claim],
            subject=subject,
            relying_party=relying_party,
        )

        # 6. Output
        print("─" * 70)
        print(envelope.summary())
        print()

        # 7. Verification
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

        # 8. Full JSON
        print("─" * 70)
        print("Full Trust Envelope (JSON):")
        print("─" * 70)
        print(envelope.to_json(indent=2))

        # 9. Save
        output_path = f"trust_envelope_mfa_{subject}.json"
        with open(output_path, "w") as f:
            f.write(envelope.to_json(indent=2))
        print(f"\n  ✓ Envelope saved to: {output_path}")


# ── CLI ─────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="OTVP AWS MFA Enforcement Agent")
    parser.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"),
                        help="AWS region (default: us-east-2)")
    parser.add_argument("--subject", default="killswitch-advisory",
                        help="Subject organization name")
    parser.add_argument("--relying-party", default=None,
                        help="Relying party organization name")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    agent = AWSMFAAgent.create(region=args.region)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))


if __name__ == "__main__":
    main()
