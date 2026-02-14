#!/usr/bin/env python3
"""
OTVP Reference Agent: AWS Encryption at Rest (LIVE)

Scans real AWS resources (RDS, S3, EBS) and produces a signed Trust Envelope.

Usage:
    export AWS_PROFILE=otvp-test
    export AWS_DEFAULT_REGION=us-east-2
    python run_agent.py

    # Or specify region:
    python run_agent.py --region us-east-2
"""
from __future__ import annotations

import asyncio
import argparse
import logging
import sys
import os

# Allow running from the SDK root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import boto3
from otvp_agent import Agent, AgentConfig, Domain, Evidence, EvidenceType, KeyPair
from otvp_agent.agents import BooleanEvaluator, Collector, CollectionContext, EvaluationResult
from otvp_agent.claims import ClaimScope

logger = logging.getLogger("otvp.agent.aws_encryption")


# ── Collectors (LIVE boto3) ─────────────────────────────────────────


class RDSEncryptionCollector(Collector):
    """Collects encryption evidence from AWS RDS instances."""
    domain = "data_protection.encryption.at_rest"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        region = context.region or "us-east-2"
        rds = boto3.client("rds", region_name=region)
        evidence_items = []

        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                evidence_items.append(
                    self.observe(
                        resource=db["DBInstanceArn"],
                        property="StorageEncrypted",
                        value=db["StorageEncrypted"],
                        expected=True,
                        metadata={
                            "engine": db["Engine"],
                            "engine_version": db["EngineVersion"],
                            "kms_key_id": db.get("KmsKeyId"),
                            "instance_class": db["DBInstanceClass"],
                            "instance_id": db["DBInstanceIdentifier"],
                            "multi_az": db.get("MultiAZ", False),
                        },
                        api="rds:DescribeDBInstances",
                        region=region,
                    )
                )
        return evidence_items


class S3EncryptionCollector(Collector):
    """Collects encryption evidence from AWS S3 buckets."""
    domain = "data_protection.encryption.at_rest"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        region = context.region or "us-east-2"
        s3 = boto3.client("s3", region_name=region)
        evidence_items = []

        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            bucket_name = bucket["Name"]

            # Check bucket location to filter by region
            try:
                loc = s3.get_bucket_location(Bucket=bucket_name)
                bucket_region = loc.get("LocationConstraint") or "us-east-1"
                if bucket_region != region:
                    continue
            except Exception as e:
                logger.warning(f"Could not get location for {bucket_name}: {e}")
                continue

            # Get encryption config
            try:
                enc = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "None")
                    kms_key = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("KMSMasterKeyID")
                    bucket_key = rules[0].get("BucketKeyEnabled", False)
                    is_kms = algo == "aws:kms"
                else:
                    algo = "None"
                    kms_key = None
                    bucket_key = False
                    is_kms = False

                evidence_items.append(
                    self.observe(
                        resource=f"arn:aws:s3:::{bucket_name}",
                        property="ServerSideEncryption",
                        value=is_kms,  # True = KMS (strong), False = SSE-S3 or none
                        expected=True,
                        metadata={
                            "bucket_name": bucket_name,
                            "algorithm": algo,
                            "kms_key_id": kms_key,
                            "bucket_key_enabled": bucket_key,
                        },
                        api="s3:GetBucketEncryption",
                        region=region,
                    )
                )
            except s3.exceptions.ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    evidence_items.append(
                        self.observe(
                            resource=f"arn:aws:s3:::{bucket_name}",
                            property="ServerSideEncryption",
                            value=False,
                            expected=True,
                            metadata={"bucket_name": bucket_name, "algorithm": "None"},
                            api="s3:GetBucketEncryption",
                            region=region,
                        )
                    )
                else:
                    logger.warning(f"Error checking encryption for {bucket_name}: {e}")

        return evidence_items


class EBSEncryptionCollector(Collector):
    """Collects encryption evidence from AWS EBS volumes."""
    domain = "data_protection.encryption.at_rest"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        region = context.region or "us-east-2"
        ec2 = boto3.client("ec2", region_name=region)
        evidence_items = []

        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                evidence_items.append(
                    self.observe(
                        resource=f"arn:aws:ec2:{region}:{boto3.client('sts').get_caller_identity()['Account']}:volume/{vol['VolumeId']}",
                        property="Encrypted",
                        value=vol["Encrypted"],
                        expected=True,
                        metadata={
                            "volume_id": vol["VolumeId"],
                            "size_gb": vol["Size"],
                            "volume_type": vol["VolumeType"],
                            "kms_key_id": vol.get("KmsKeyId"),
                            "state": vol["State"],
                            "availability_zone": vol["AvailabilityZone"],
                        },
                        api="ec2:DescribeVolumes",
                        region=region,
                    )
                )
        return evidence_items


# ── Evaluator ───────────────────────────────────────────────────────


class EncryptionAtRestEvaluator(BooleanEvaluator):
    domain = "data_protection.encryption.at_rest"
    assertion = "All production storage resources are encrypted at rest"
    property_name = "encryption_enabled"
    expected_value = True


# ── Composite Agent ─────────────────────────────────────────────────


class AWSEncryptionAgent:
    def __init__(self, agent: Agent, region: str = "us-east-2") -> None:
        self.agent = agent
        self.region = region
        self.collectors = [
            RDSEncryptionCollector(),
            S3EncryptionCollector(),
            EBSEncryptionCollector(),
        ]
        self.evaluator = EncryptionAtRestEvaluator()

    @classmethod
    def create(cls, region: str = "us-east-2") -> AWSEncryptionAgent:
        keys = KeyPair.generate()
        config = AgentConfig(
            agent_id="aws-encryption-agent-v1",
            vendor="OTVP Reference / Killswitch Advisory",
            version="1.0.0",
            key_pair=keys,
            domains=[Domain.ENCRYPTION_AT_REST],
        )
        agent = Agent(config)
        return cls(agent=agent, region=region)

    async def run(self, subject: str = "killswitch-advisory",
                  relying_party: str | None = None) -> None:
        ctx = CollectionContext(environment="test", region=self.region)

        print("=" * 70)
        print("  OTVP Reference Agent: AWS Encryption at Rest")
        print(f"  Region: {self.region}")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        # 1. Collect
        all_evidence: list[Evidence] = []
        for collector in self.collectors:
            items = await collector.collect(ctx)
            all_evidence.extend(items)
            print(f"  ✓ Collected {len(items)} items from {collector.__class__.__name__}")

        print(f"\n  Total evidence: {len(all_evidence)}")
        print()

        # 2. Sign and store
        signed_refs = []
        for ev in all_evidence:
            signed = self.agent.sign_evidence(ev)
            signed_refs.append(signed.evidence_id)

        # 3. Evaluate
        result = await self.evaluator.evaluate(all_evidence)
        print(f"  Evaluation: {result.result.value}")
        print(f"  Confidence: {result.confidence:.0%}")
        print(f"  Assessment: {result.assessment}")
        if result.caveats:
            for c in result.caveats:
                print(f"  ⚠ Caveat: {c}")
        print()

        # 4. Create signed claim
        claim = self.agent.create_claim(
            domain="data_protection.encryption.at_rest",
            assertion=self.evaluator.assertion,
            result=result.result,
            confidence=result.confidence,
            evidence_refs=signed_refs,
            opinion=result.assessment,
            caveats=result.caveats,
            scope=ClaimScope(
                environment="test",
                services=["RDS", "S3", "EBS"],
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

        # Verify individual evidence proofs
        store = self.agent.evidence_store
        for i in range(min(3, store.size)):
            proof = store.get_proof(i)
            print(f"  Evidence [{i}] Merkle proof valid: {proof.verify()}")
        print()

        # 8. Full JSON envelope
        print("─" * 70)
        print("Full Trust Envelope (JSON):")
        print("─" * 70)
        print(envelope.to_json(indent=2))

        # 9. Save envelope to file
        output_path = f"trust_envelope_{subject}.json"
        with open(output_path, "w") as f:
            f.write(envelope.to_json(indent=2))
        print(f"\n  ✓ Envelope saved to: {output_path}")


# ── CLI ─────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="OTVP AWS Encryption Agent")
    parser.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"),
                        help="AWS region (default: us-east-2)")
    parser.add_argument("--subject", default="killswitch-advisory",
                        help="Subject organization name")
    parser.add_argument("--relying-party", default=None,
                        help="Relying party organization name")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    agent = AWSEncryptionAgent.create(region=args.region)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))


if __name__ == "__main__":
    main()
