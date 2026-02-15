#!/usr/bin/env python3
"""
OTVP Reference Agent: Account Lifecycle

Identifies stale IAM accounts, unused access keys, and orphaned credentials.
Maps to SOC 2 CC6.2, CC6.5 | ISO 27001 A.9.2.6 | NIST CSF PR.AC-1

Usage:
    export AWS_PROFILE=otvp-test
    python run_lifecycle_agent.py
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

logger = logging.getLogger("otvp.agent.aws_lifecycle")

STALE_DAYS = 90
KEY_STALE_DAYS = 90


class AccountLifecycleCollector(Collector):
    domain = "identity_and_access.lifecycle.provisioning"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        region = context.region or "us-east-2"
        iam = boto3.client("iam", region_name=region)
        evidence_items = []
        now = datetime.now(timezone.utc)

        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                user_arn = user["Arn"]
                create_date = user["CreateDate"]
                password_last_used = user.get("PasswordLastUsed")

                # Check console login staleness
                has_console = False
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchEntity":
                        logger.warning(f"Error checking login profile for {username}: {e}")

                console_stale = False
                days_since_login = None
                if has_console and password_last_used:
                    days_since_login = (now - password_last_used.replace(tzinfo=timezone.utc)).days
                    console_stale = days_since_login > STALE_DAYS
                elif has_console and not password_last_used:
                    console_stale = True
                    days_since_login = (now - create_date.replace(tzinfo=timezone.utc)).days

                # Check access keys
                stale_keys = []
                active_keys = 0
                try:
                    keys_resp = iam.list_access_keys(UserName=username)
                    for key in keys_resp.get("AccessKeyMetadata", []):
                        if key["Status"] != "Active":
                            continue
                        active_keys += 1
                        key_id = key["AccessKeyId"]
                        try:
                            last_used = iam.get_access_key_last_used(AccessKeyId=key_id)
                            lu_info = last_used.get("AccessKeyLastUsed", {})
                            last_used_date = lu_info.get("LastUsedDate")
                            if last_used_date:
                                days_unused = (now - last_used_date.replace(tzinfo=timezone.utc)).days
                            else:
                                days_unused = (now - key["CreateDate"].replace(tzinfo=timezone.utc)).days
                            if days_unused > KEY_STALE_DAYS:
                                stale_keys.append({"key_id": key_id, "days_unused": days_unused})
                        except ClientError:
                            pass
                except ClientError as e:
                    logger.warning(f"Error listing keys for {username}: {e}")

                is_healthy = not console_stale and len(stale_keys) == 0

                evidence_items.append(
                    self.observe(
                        resource=user_arn,
                        property="AccountHealthy",
                        value=is_healthy,
                        expected=True,
                        metadata={
                            "username": username,
                            "has_console_access": has_console,
                            "console_stale": console_stale,
                            "days_since_login": days_since_login,
                            "active_access_keys": active_keys,
                            "stale_access_keys": stale_keys,
                            "stale_key_count": len(stale_keys),
                            "account_age_days": (now - create_date.replace(tzinfo=timezone.utc)).days,
                            "created": create_date.isoformat(),
                        },
                        api="iam:ListUsers,iam:GetLoginProfile,iam:ListAccessKeys,iam:GetAccessKeyLastUsed",
                        region="global",
                    )
                )

        return evidence_items


class AccountLifecycleEvaluator:
    domain = "identity_and_access.lifecycle.provisioning"
    assertion = "All IAM accounts are actively used with no stale credentials"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.INDETERMINATE, confidence=0.0,
                                    assessment="No IAM users found.")

        healthy = []
        unhealthy = []
        stale_consoles = []
        stale_keys_found = []

        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            meta = obs.get("metadata", {})
            username = meta.get("username", "unknown")
            is_healthy = obs.get("value", False)

            if is_healthy:
                healthy.append(username)
            else:
                unhealthy.append(username)
                if meta.get("console_stale"):
                    days = meta.get("days_since_login", "?")
                    stale_consoles.append(f"{username} (no login in {days}d)")
                for sk in meta.get("stale_access_keys", []):
                    stale_keys_found.append(f"{username}/{sk['key_id']} (unused {sk['days_unused']}d)")

        total = len(evidence_items)
        pct = len(healthy) / total if total > 0 else 0
        caveats = []
        recommendations = []

        if stale_consoles:
            caveats.append(f"Stale console accounts (>{STALE_DAYS}d): {', '.join(stale_consoles)}")
            recommendations.append("Disable or remove console access for inactive users")
        if stale_keys_found:
            caveats.append(f"Stale access keys (>{KEY_STALE_DAYS}d): {', '.join(stale_keys_found[:5])}")
            recommendations.append("Deactivate or rotate unused access keys")

        if pct == 1.0:
            conf = min(0.99, 0.85 + 0.14 * min(total / 10, 1.0))
            return EvaluationResult(result=ClaimResult.SATISFIED, confidence=round(conf, 3),
                assessment=f"All {total} IAM account(s) are actively used with no stale credentials.",
                caveats=caveats, evidence_ids=[e.evidence_id for e in evidence_items])
        elif pct > 0.5:
            return EvaluationResult(result=ClaimResult.PARTIAL, confidence=round(pct * 0.85, 3),
                assessment=f"{len(healthy)}/{total} IAM accounts are healthy. {len(unhealthy)} have stale credentials.",
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])
        else:
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=0.95,
                assessment=f"Only {len(healthy)}/{total} IAM accounts are healthy.",
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])


class AWSLifecycleAgent:
    def __init__(self, agent: Agent, region: str = "us-east-2") -> None:
        self.agent = agent
        self.region = region
        self.collector = AccountLifecycleCollector()
        self.evaluator = AccountLifecycleEvaluator()

    @classmethod
    def create(cls, region: str = "us-east-2") -> AWSLifecycleAgent:
        keys = KeyPair.generate()
        config = AgentConfig(agent_id="aws-lifecycle-agent-v1", vendor="OTVP Reference / Killswitch Advisory",
            version="1.0.0", key_pair=keys, domains=["identity_and_access.lifecycle.provisioning"])
        return cls(agent=Agent(config), region=region)

    async def run(self, subject: str = "killswitch-advisory", relying_party: str | None = None) -> None:
        ctx = CollectionContext(environment="test", region=self.region)
        print("=" * 70)
        print("  OTVP Reference Agent: Account Lifecycle")
        print(f"  Region: global (IAM)")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        evidence = await self.collector.collect(ctx)
        print(f"  ✓ Collected {len(evidence)} IAM account lifecycle evidence items")
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
            scope=ClaimScope(environment="test", services=["IAM"], regions=["global"]))

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
        output_path = f"trust_envelope_lifecycle_{subject}.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  ✓ Envelope saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="OTVP AWS Account Lifecycle Agent")
    parser.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    agent = AWSLifecycleAgent.create(region=args.region)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
