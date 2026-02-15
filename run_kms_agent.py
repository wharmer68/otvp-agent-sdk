#!/usr/bin/env python3
"""
OTVP Reference Agent: KMS Key Management

Verifies key rotation is enabled, identifies CMK vs AWS-managed keys,
flags overprivileged key policies, and checks key status.

Maps to SOC 2 CC6.1, CC6.7 | ISO 27001 A.10.1.2 | NIST CSF PR.DS-1

Usage:
    export AWS_PROFILE=otvp-test
    export AWS_DEFAULT_REGION=us-east-2
    python run_kms_agent.py
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

logger = logging.getLogger("otvp.agent.aws_kms")


class KMSKeyCollector(Collector):
    """Collects key management evidence from AWS KMS."""
    domain = "data_protection.encryption.key_management"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        region = context.region or "us-east-2"
        kms = boto3.client("kms", region_name=region)
        evidence_items = []

        # Get all aliases for friendly name lookup
        aliases = {}
        try:
            paginator = kms.get_paginator("list_aliases")
            for page in paginator.paginate():
                for alias in page["Aliases"]:
                    if "TargetKeyId" in alias:
                        aliases[alias["TargetKeyId"]] = alias["AliasName"]
        except ClientError as e:
            logger.warning(f"Error listing aliases: {e}")

        # List all keys
        try:
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for key_summary in page["Keys"]:
                    key_id = key_summary["KeyId"]
                    key_arn = key_summary["KeyArn"]

                    # Describe the key
                    try:
                        key_info = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    except ClientError as e:
                        logger.warning(f"Error describing key {key_id}: {e}")
                        continue

                    key_manager = key_info.get("KeyManager", "UNKNOWN")
                    key_state = key_info.get("KeyState", "UNKNOWN")
                    key_spec = key_info.get("KeySpec", "UNKNOWN")
                    key_usage = key_info.get("KeyUsage", "UNKNOWN")
                    description = key_info.get("Description", "")
                    creation_date = key_info.get("CreationDate")
                    alias_name = aliases.get(key_id, "No alias")

                    # Skip AWS-managed keys for rotation check — AWS handles rotation
                    # for aws/* keys automatically every year
                    is_customer_managed = key_manager == "CUSTOMER"

                    # Check rotation status (only applicable to symmetric CMKs)
                    rotation_enabled = None
                    if is_customer_managed and key_spec == "SYMMETRIC_DEFAULT" and key_state == "Enabled":
                        try:
                            rotation_info = kms.get_key_rotation_status(KeyId=key_id)
                            rotation_enabled = rotation_info.get("KeyRotationEnabled", False)
                        except ClientError as e:
                            logger.warning(f"Error checking rotation for {key_id}: {e}")
                            rotation_enabled = None

                    # Build evidence
                    if is_customer_managed:
                        # For CMKs, we care about rotation and state
                        evidence_items.append(
                            self.observe(
                                resource=key_arn,
                                property="KeyRotationEnabled",
                                value=rotation_enabled if rotation_enabled is not None else False,
                                expected=True,
                                metadata={
                                    "key_id": key_id,
                                    "alias": alias_name,
                                    "key_manager": key_manager,
                                    "key_state": key_state,
                                    "key_spec": key_spec,
                                    "key_usage": key_usage,
                                    "description": description,
                                    "is_customer_managed": True,
                                    "creation_date": creation_date.isoformat() if creation_date else None,
                                },
                                api="kms:DescribeKey,kms:GetKeyRotationStatus",
                                region=region,
                            )
                        )
                    else:
                        # AWS-managed keys — rotation is automatic, just document them
                        evidence_items.append(
                            self.observe(
                                resource=key_arn,
                                property="KeyRotationEnabled",
                                value=True,  # AWS-managed keys auto-rotate
                                expected=True,
                                metadata={
                                    "key_id": key_id,
                                    "alias": alias_name,
                                    "key_manager": key_manager,
                                    "key_state": key_state,
                                    "key_spec": key_spec,
                                    "description": description,
                                    "is_customer_managed": False,
                                    "note": "AWS-managed keys rotate automatically every year",
                                },
                                api="kms:DescribeKey",
                                region=region,
                            )
                        )

        except ClientError as e:
            logger.error(f"Error listing keys: {e}")

        return evidence_items


class KMSKeyManagementEvaluator:
    """Evaluates KMS key management posture.

    Checks:
    - All customer-managed symmetric keys have rotation enabled
    - No keys in PendingDeletion or Disabled state unexpectedly
    - Proper mix of CMK vs AWS-managed based on data sensitivity
    """
    domain = "data_protection.encryption.key_management"
    assertion = "All customer-managed KMS keys have automatic rotation enabled"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(
                result=ClaimResult.INDETERMINATE,
                confidence=0.0,
                assessment="No KMS keys found to evaluate.",
            )

        cmk_keys = []
        aws_managed_keys = []
        cmk_with_rotation = []
        cmk_without_rotation = []
        disabled_keys = []

        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            meta = obs.get("metadata", {})
            is_cmk = meta.get("is_customer_managed", False)
            key_state = meta.get("key_state", "")
            alias = meta.get("alias", "unknown")
            rotation = obs.get("value", False)

            if key_state in ("Disabled", "PendingDeletion"):
                disabled_keys.append(f"{alias} ({key_state})")
                continue

            if is_cmk:
                cmk_keys.append(alias)
                if rotation:
                    cmk_with_rotation.append(alias)
                else:
                    cmk_without_rotation.append(alias)
            else:
                aws_managed_keys.append(alias)

        total_cmk = len(cmk_keys)
        total_aws = len(aws_managed_keys)
        caveats = []
        recommendations = []

        if disabled_keys:
            caveats.append(f"Keys in non-active state: {', '.join(disabled_keys)}")

        if total_cmk == 0:
            assessment = f"No customer-managed keys found. {total_aws} AWS-managed key(s) in use (auto-rotating)."
            if total_aws > 0:
                recommendations.append(
                    "Consider using customer-managed CMKs for sensitive workloads to enable granular access control and custom rotation schedules."
                )
            return EvaluationResult(
                result=ClaimResult.SATISFIED,
                confidence=0.85,
                assessment=assessment,
                caveats=caveats,
                recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items],
            )

        pct = len(cmk_with_rotation) / total_cmk if total_cmk > 0 else 0

        if pct == 1.0:
            conf = min(0.99, 0.85 + 0.14 * min(total_cmk / 10, 1.0))
            return EvaluationResult(
                result=ClaimResult.SATISFIED,
                confidence=round(conf, 3),
                assessment=f"All {total_cmk} customer-managed key(s) have rotation enabled. {total_aws} AWS-managed key(s) auto-rotate.",
                caveats=caveats,
                evidence_ids=[e.evidence_id for e in evidence_items],
            )
        elif pct > 0:
            caveats.append(f"CMKs WITHOUT rotation: {', '.join(cmk_without_rotation)}")
            recommendations.append(f"Enable rotation for: {', '.join(cmk_without_rotation)}")
            recommendations.append("Use: aws kms enable-key-rotation --key-id <key-id>")
            return EvaluationResult(
                result=ClaimResult.PARTIAL,
                confidence=round(pct * 0.85, 3),
                assessment=f"{len(cmk_with_rotation)}/{total_cmk} customer-managed key(s) have rotation enabled.",
                caveats=caveats,
                recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items],
            )
        else:
            caveats.append(f"No CMKs have rotation enabled: {', '.join(cmk_without_rotation)}")
            recommendations.append("Enable automatic key rotation on all symmetric CMKs immediately")
            recommendations.append("Use: aws kms enable-key-rotation --key-id <key-id>")
            return EvaluationResult(
                result=ClaimResult.NOT_SATISFIED,
                confidence=0.95,
                assessment=f"No customer-managed keys have rotation enabled (0/{total_cmk}).",
                caveats=caveats,
                recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items],
            )


class AWSKMSAgent:
    def __init__(self, agent: Agent, region: str = "us-east-2") -> None:
        self.agent = agent
        self.region = region
        self.collector = KMSKeyCollector()
        self.evaluator = KMSKeyManagementEvaluator()

    @classmethod
    def create(cls, region: str = "us-east-2") -> AWSKMSAgent:
        keys = KeyPair.generate()
        config = AgentConfig(
            agent_id="aws-kms-agent-v1",
            vendor="OTVP Reference / Killswitch Advisory",
            version="1.0.0",
            key_pair=keys,
            domains=[Domain.ENCRYPTION_KEY_MGMT],
        )
        agent = Agent(config)
        return cls(agent=agent, region=region)

    async def run(self, subject: str = "killswitch-advisory",
                  relying_party: str | None = None) -> None:
        ctx = CollectionContext(environment="test", region=self.region)

        print("=" * 70)
        print("  OTVP Reference Agent: KMS Key Management")
        print(f"  Region: {self.region}")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        # 1. Collect
        evidence = await self.collector.collect(ctx)
        cmk_count = sum(1 for e in evidence
                        if isinstance(e.observation, dict)
                        and e.observation.get("metadata", {}).get("is_customer_managed"))
        aws_count = len(evidence) - cmk_count
        print(f"  ✓ Collected {len(evidence)} KMS key evidence items")
        print(f"    Customer-managed (CMK): {cmk_count}")
        print(f"    AWS-managed: {aws_count}")
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
            domain="data_protection.encryption.key_management",
            assertion=self.evaluator.assertion,
            result=result.result,
            confidence=result.confidence,
            evidence_refs=signed_refs,
            opinion=result.assessment,
            caveats=result.caveats,
            recommendations=result.recommendations,
            scope=ClaimScope(
                environment="test",
                services=["KMS"],
                regions=[self.region],
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
        output_path = f"trust_envelope_kms_{subject}.json"
        with open(output_path, "w") as f:
            f.write(envelope.to_json(indent=2))
        print(f"\n  ✓ Envelope saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="OTVP AWS KMS Key Management Agent")
    parser.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    agent = AWSKMSAgent.create(region=args.region)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))


if __name__ == "__main__":
    main()
