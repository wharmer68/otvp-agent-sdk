#!/usr/bin/env python3
"""
OTVP Reference Agent: Backup & Recovery

Verifies AWS Backup plan coverage, snapshot existence, and recovery readiness.
Maps to SOC 2 CC7.5, CC9.1 | ISO 27001 A.12.3.1 | NIST CSF PR.IP-4

Usage:
    export AWS_PROFILE=otvp-test
    python run_backup_agent.py
"""
from __future__ import annotations

import asyncio
import argparse
import logging
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import boto3
from botocore.exceptions import ClientError
from otvp_agent import Agent, AgentConfig, KeyPair, Evidence
from otvp_agent.agents import Collector, CollectionContext, EvaluationResult
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.aws_backup")


class BackupCollector(Collector):
    domain = "operational_resilience.backup.coverage"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        region = context.region or "us-east-2"
        evidence_items = []

        # Check AWS Backup plans
        backup_plans_exist = False
        protected_resources = set()
        try:
            backup = boto3.client("backup", region_name=region)
            plans = backup.list_backup_plans().get("BackupPlansList", [])
            backup_plans_exist = len(plans) > 0

            evidence_items.append(self.observe(
                resource=f"arn:aws:backup:{region}::plans",
                property="BackupPlansExist", value=backup_plans_exist, expected=True,
                metadata={"plan_count": len(plans),
                          "plan_names": [p.get("BackupPlanName","?") for p in plans]},
                api="backup:ListBackupPlans", region=region))

            # Check protected resources
            if backup_plans_exist:
                try:
                    protected = backup.list_protected_resources().get("Results", [])
                    protected_resources = {r.get("ResourceArn","") for r in protected}

                    evidence_items.append(self.observe(
                        resource=f"arn:aws:backup:{region}::protected",
                        property="ResourcesProtected", value=len(protected) > 0, expected=True,
                        metadata={"protected_count": len(protected),
                                  "resource_types": list({r.get("ResourceType","?") for r in protected})},
                        api="backup:ListProtectedResources", region=region))
                except ClientError as e:
                    logger.warning(f"Error listing protected resources: {e}")

        except ClientError as e:
            logger.info(f"AWS Backup: {e}")
            evidence_items.append(self.observe(
                resource=f"arn:aws:backup:{region}::plans",
                property="BackupPlansExist", value=False, expected=True,
                metadata={"note": "AWS Backup not configured or not accessible"},
                api="backup:ListBackupPlans", region=region))

        # Check RDS snapshots
        try:
            rds = boto3.client("rds", region_name=region)
            instances = rds.describe_db_instances().get("DBInstances", [])
            for db in instances:
                db_id = db["DBInstanceIdentifier"]
                db_arn = db["DBInstanceArn"]

                # Check automated backups
                retention = db.get("BackupRetentionPeriod", 0)
                has_backups = retention > 0
                in_backup_plan = db_arn in protected_resources

                # Check for recent snapshots
                snapshots = rds.describe_db_snapshots(
                    DBInstanceIdentifier=db_id, SnapshotType="automated",
                    MaxRecords=5).get("DBSnapshots", [])
                recent_snapshot = None
                if snapshots:
                    latest = sorted(snapshots, key=lambda s: s.get("SnapshotCreateTime", datetime.min.replace(tzinfo=timezone.utc)), reverse=True)[0]
                    recent_snapshot = latest.get("SnapshotCreateTime")

                is_protected = has_backups or in_backup_plan

                evidence_items.append(self.observe(
                    resource=db_arn, property="BackupConfigured", value=is_protected, expected=True,
                    metadata={"db_instance": db_id, "resource_type": "RDS",
                              "backup_retention_days": retention,
                              "in_aws_backup_plan": in_backup_plan,
                              "recent_snapshot": recent_snapshot.isoformat() if recent_snapshot else None,
                              "snapshot_count": len(snapshots)},
                    api="rds:DescribeDBInstances,rds:DescribeDBSnapshots", region=region))
        except ClientError as e:
            logger.warning(f"Error checking RDS backups: {e}")

        # Check EBS snapshots
        try:
            ec2 = boto3.client("ec2", region_name=region)
            volumes = ec2.describe_volumes().get("Volumes", [])
            account_id = boto3.client("sts").get_caller_identity()["Account"]

            for vol in volumes:
                vol_id = vol["VolumeId"]
                vol_arn = f"arn:aws:ec2:{region}:{account_id}:volume/{vol_id}"
                in_backup_plan = vol_arn in protected_resources

                # Check for snapshots of this volume
                try:
                    snaps = ec2.describe_snapshots(Filters=[
                        {"Name": "volume-id", "Values": [vol_id]}],
                        OwnerIds=["self"], MaxResults=5).get("Snapshots", [])
                except ClientError:
                    snaps = []

                is_protected = in_backup_plan or len(snaps) > 0

                evidence_items.append(self.observe(
                    resource=vol_arn, property="BackupConfigured", value=is_protected, expected=True,
                    metadata={"volume_id": vol_id, "resource_type": "EBS",
                              "size_gb": vol["Size"], "in_aws_backup_plan": in_backup_plan,
                              "snapshot_count": len(snaps)},
                    api="ec2:DescribeVolumes,ec2:DescribeSnapshots", region=region))
        except ClientError as e:
            logger.warning(f"Error checking EBS backups: {e}")

        return evidence_items


class BackupEvaluator:
    domain = "operational_resilience.backup.coverage"
    assertion = "All critical data stores have backup protection configured"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.INDETERMINATE, confidence=0.0,
                                    assessment="No backup data collected.")

        caveats = []
        recommendations = []
        has_backup_plans = False
        resource_checks = []
        protected = []
        unprotected = []

        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            meta = obs.get("metadata", {})
            prop = obs.get("property", "")
            value = obs.get("value", False)

            if prop == "BackupPlansExist":
                has_backup_plans = value
                if not value:
                    caveats.append("No AWS Backup plans configured")
                    recommendations.append("Create an AWS Backup plan covering all critical resources")

            elif prop == "ResourcesProtected":
                if not value:
                    caveats.append("No resources protected by AWS Backup")

            elif prop == "BackupConfigured":
                rtype = meta.get("resource_type", "?")
                name = meta.get("db_instance", meta.get("volume_id", "?"))
                resource_checks.append(item)
                if value:
                    protected.append(f"{rtype}:{name}")
                else:
                    unprotected.append(f"{rtype}:{name}")
                    caveats.append(f"{rtype} {name}: no backup configured")

        if unprotected:
            recommendations.append(f"Add backup coverage for: {', '.join(unprotected)}")

        total = len(resource_checks)
        if total == 0:
            conf = 1.0
            return EvaluationResult(
                result=ClaimResult.PARTIAL if has_backup_plans else ClaimResult.NOT_SATISFIED,
                confidence=conf,
                assessment="No data store resources found to verify backup coverage." +
                          (" AWS Backup plans exist." if has_backup_plans else " No backup infrastructure."),
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])

        pct = len(protected) / total if total > 0 else 0

        if pct == 1.0:
            conf = 1.0
            return EvaluationResult(result=ClaimResult.SATISFIED, confidence=conf,
                assessment=f"All {total} data store(s) have backup protection. {len(protected)} resource(s) covered.",
                caveats=caveats, evidence_ids=[e.evidence_id for e in evidence_items])
        elif pct > 0.5:
            return EvaluationResult(result=ClaimResult.PARTIAL, confidence=round(pct, 3),
                assessment=f"{len(protected)}/{total} data stores have backup coverage.",
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])
        else:
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=1.0,
                assessment=f"Only {len(protected)}/{total} data stores have backup coverage.",
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])


class AWSBackupAgent:
    def __init__(self, agent, region="us-east-2"):
        self.agent = agent; self.region = region
        self.collector = BackupCollector()
        self.evaluator = BackupEvaluator()

    @classmethod
    def create(cls, region="us-east-2"):
        keys = KeyPair.generate()
        config = __import__('otvp_agent').AgentConfig(agent_id="aws-backup-agent-v1",
            vendor="OTVP Reference / Killswitch Advisory", version="1.0.0", key_pair=keys,
            domains=["operational_resilience.backup.coverage"])
        return cls(agent=Agent(config), region=region)

    async def run(self, subject="killswitch-advisory", relying_party=None):
        ctx = CollectionContext(environment="test", region=self.region)
        print("=" * 70)
        print("  OTVP Reference Agent: Backup & Recovery")
        print(f"  Region: {self.region}")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        evidence = await self.collector.collect(ctx)
        print(f"  ✓ Collected {len(evidence)} backup evidence items")
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
            scope=ClaimScope(environment="test", services=["AWS Backup", "RDS", "EBS"], regions=[self.region]))

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
        output_path = f"trust_envelope_backup_{subject}.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  ✓ Envelope saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="OTVP AWS Backup & Recovery Agent")
    parser.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    agent = AWSBackupAgent.create(region=args.region)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
