#!/usr/bin/env python3
"""
OTVP Supabase Agent: Storage Bucket Policy

Verifies that Supabase Storage buckets have appropriate access controls:
public vs. private bucket classification, RLS policies on storage.objects,
and file size / MIME type restrictions.

Maps to SOC 2 CC6.1, CC6.7.

Usage:
    export SUPABASE_DB_HOST=... SUPABASE_DB_PORT=6543 SUPABASE_DB_USER=...
    export SUPABASE_DB_PASSWORD=... SUPABASE_PROJECT_REF=...
    python run_supabase_storage_agent.py
"""
from __future__ import annotations

import asyncio
import argparse
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from otvp_agent import Agent, AgentConfig, Domain, Evidence, EvidenceType, KeyPair
from otvp_agent.agents import CollectionContext, EvaluationResult
from otvp_agent.agents.supabase.base import SupabaseCollector, SupabaseEvaluator
from otvp_agent.agents.supabase.connection import SupabaseConnection
from otvp_agent.agents.supabase.constants import DOMAIN_STORAGE_BUCKETS
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.supabase_storage")

SQL_BUCKETS = """
SELECT id, name, public, file_size_limit, allowed_mime_types,
       created_at, updated_at
FROM storage.buckets
ORDER BY name;
"""

SQL_STORAGE_RLS_ENABLED = """
SELECT schemaname, tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'storage'
AND tablename = 'objects'
ORDER BY tablename;
"""

SQL_STORAGE_POLICIES = """
SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
FROM pg_policies
WHERE schemaname = 'storage'
AND tablename = 'objects'
ORDER BY policyname;
"""


class StorageBucketCollector(SupabaseCollector):
    domain = DOMAIN_STORAGE_BUCKETS

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        conn = self.connection
        if conn is None:
            raise RuntimeError("StorageBucketCollector requires a SupabaseConnection.")

        evidence_items: list[Evidence] = []

        # 1. Bucket inventory
        buckets = conn.execute(SQL_BUCKETS)
        public_buckets = [b for b in buckets if b.get("public")]
        private_buckets = [b for b in buckets if not b.get("public")]

        for bucket in buckets:
            is_public = bucket.get("public", False)
            has_size_limit = bucket.get("file_size_limit") is not None
            has_mime_filter = (
                bucket.get("allowed_mime_types") is not None
                and len(bucket.get("allowed_mime_types") or []) > 0
            )

            risk_flags = []
            if is_public:
                risk_flags.append("public_bucket")
            if not has_size_limit:
                risk_flags.append("no_file_size_limit")
            if not has_mime_filter:
                risk_flags.append("no_mime_type_restriction")

            passed = not is_public  # Private buckets pass by default
            severity = "medium" if is_public else "none"

            evidence_items.append(self.make_evidence(
                resource_id=f"storage.bucket.{bucket['name']}",
                observation={
                    "check": "bucket_access_control",
                    "bucket_name": bucket["name"],
                    "bucket_id": bucket["id"],
                    "is_public": is_public,
                    "file_size_limit": bucket.get("file_size_limit"),
                    "allowed_mime_types": bucket.get("allowed_mime_types"),
                    "has_size_limit": has_size_limit,
                    "has_mime_filter": has_mime_filter,
                    "risk_flags": risk_flags,
                    "passed": passed,
                    "severity": severity,
                    "detail": (
                        f"Bucket '{bucket['name']}' is {'PUBLIC' if is_public else 'private'}"
                        f"{', no size limit' if not has_size_limit else ''}"
                        f"{', no MIME filter' if not has_mime_filter else ''}."
                    ),
                },
                tags={"framework": "soc2", "criteria": "CC6.1,CC6.7", "agent": "supabase-storage-buckets"},
            ))

        # 2. RLS on storage.objects
        rls_rows = conn.execute(SQL_STORAGE_RLS_ENABLED)
        objects_table = next((r for r in rls_rows if r["tablename"] == "objects"), None)
        rls_enabled = objects_table.get("rowsecurity", False) if objects_table else False

        evidence_items.append(self.make_evidence(
            resource_id="storage.objects_rls",
            observation={
                "check": "storage_objects_rls",
                "rls_enabled": rls_enabled,
                "passed": rls_enabled,
                "severity": "critical" if not rls_enabled else "none",
                "detail": (
                    "RLS is enabled on storage.objects."
                    if rls_enabled else
                    "RLS is DISABLED on storage.objects — all storage access is unrestricted!"
                ),
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.7", "agent": "supabase-storage-buckets"},
        ))

        # 3. Storage policies
        policies = conn.execute(SQL_STORAGE_POLICIES)
        evidence_items.append(self.make_evidence(
            resource_id="storage.objects_policies",
            observation={
                "check": "storage_policy_inventory",
                "policy_count": len(policies),
                "policies": [
                    {
                        "name": p["policyname"],
                        "command": p["cmd"],
                        "roles": p["roles"],
                        "permissive": p["permissive"],
                    }
                    for p in policies[:30]
                ],
                "passed": len(policies) > 0,
                "severity": "high" if len(policies) == 0 else "none",
                "detail": (
                    f"{len(policies)} RLS polic(ies) defined on storage.objects."
                    if policies else
                    "No RLS policies on storage.objects — even with RLS enabled, "
                    "default-deny means NO access (but policies should be explicit)."
                ),
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.7", "agent": "supabase-storage-buckets"},
        ))

        # Summary evidence
        evidence_items.append(self.make_evidence(
            resource_id="storage.summary",
            observation={
                "check": "bucket_summary",
                "total_buckets": len(buckets),
                "public_count": len(public_buckets),
                "private_count": len(private_buckets),
                "passed": len(public_buckets) == 0,
                "severity": "medium" if public_buckets else "none",
                "detail": (
                    f"{len(buckets)} bucket(s): {len(public_buckets)} public, {len(private_buckets)} private."
                ),
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.7", "agent": "supabase-storage-buckets"},
        ))

        return evidence_items


class StorageBucketEvaluator(SupabaseEvaluator):
    domain = DOMAIN_STORAGE_BUCKETS
    assertion = "Supabase Storage buckets have appropriate access controls with RLS policies protecting object access"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.INDETERMINATE, confidence=0.0,
                                    assessment="No storage bucket evidence collected.", evidence_ids=[])

        passed, failed = [], []
        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            if obs.get("passed", False):
                passed.append(obs.get("check", "?"))
            else:
                failed.append({"check": obs.get("check", "?"), "severity": obs.get("severity", "none"), "detail": obs.get("detail", "")})

        total = len(evidence_items)
        all_ids = [e.evidence_id for e in evidence_items]

        if len(passed) == total:
            return EvaluationResult(result=ClaimResult.SATISFIED, confidence=1.0,
                                    assessment=f"All {total} storage checks pass.", evidence_ids=all_ids)
        if not passed:
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=1.0,
                                    assessment=f"All {total} storage checks have issues.",
                                    caveats=[f"{f['check']}: {f['detail']}" for f in failed],
                                    recommendations=[_storage_rec(f) for f in failed[:5]], evidence_ids=all_ids)

        confidence = round(len(passed) / total, 3)
        return EvaluationResult(result=ClaimResult.PARTIAL, confidence=confidence,
                                assessment=f"{len(passed)}/{total} storage checks pass.",
                                caveats=[f"{f['check']} [{f['severity']}]: {f['detail']}" for f in failed],
                                recommendations=[_storage_rec(f) for f in failed[:5]], evidence_ids=all_ids)


def _storage_rec(f: dict) -> str:
    check = f["check"]
    if check == "storage_objects_rls":
        return "Enable RLS on storage.objects: ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;"
    if check == "bucket_access_control":
        return "Review public buckets — set to private unless public access is intentional: UPDATE storage.buckets SET public = false WHERE name = '<bucket>';"
    if check == "storage_policy_inventory":
        return "Create RLS policies on storage.objects to control per-bucket and per-user access."
    if check == "bucket_summary":
        return "Minimize public buckets. Each public bucket allows unauthenticated downloads of all objects."
    return f"Review: {f['detail']}"


class SupabaseStorageAgent:
    def __init__(self, agent: Agent, connection: SupabaseConnection) -> None:
        self.agent = agent
        self.connection = connection
        self.collector = StorageBucketCollector()
        self.evaluator = StorageBucketEvaluator()

    @classmethod
    def create(cls, project_ref: str | None = None) -> SupabaseStorageAgent:
        keys = KeyPair.generate()
        config = AgentConfig(agent_id="supabase-storage-agent-v1", vendor="OTVP Reference / Killswitch Advisory",
                             version="1.0.0", key_pair=keys, domains=[Domain.STORAGE_BUCKETS])
        return cls(agent=Agent(config), connection=SupabaseConnection(project_ref=project_ref))

    async def run(self, subject: str = "killswitch-advisory", relying_party: str | None = None) -> None:
        project_ref = self.connection.project_ref or "(unknown)"
        print("=" * 70)
        print("  OTVP Supabase Agent: Storage Bucket Policy")
        print(f"  Project: {project_ref}")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        with self.connection as conn:
            self.collector.connection = conn
            ctx = CollectionContext(environment="production", custom={"project_ref": project_ref})
            evidence = await self.collector.collect(ctx)

        passed = sum(1 for e in evidence if isinstance(e.observation, dict) and e.observation.get("passed"))
        print(f"  Collected {len(evidence)} evidence items (passed: {passed}, failed: {len(evidence) - passed})")
        print()

        signed_refs = [self.agent.sign_evidence(ev).evidence_id for ev in evidence]
        result = await self.evaluator.evaluate(evidence)
        print(f"  Evaluation: {result.result.value}")
        print(f"  Confidence: {result.confidence:.0%}")
        print(f"  Assessment: {result.assessment}")
        for c in result.caveats: print(f"  ! {c}")
        for r in result.recommendations: print(f"  > {r}")
        print()

        claim = self.agent.create_claim(domain=DOMAIN_STORAGE_BUCKETS, assertion=self.evaluator.assertion,
                                         result=result.result, confidence=result.confidence, evidence_refs=signed_refs,
                                         opinion=result.assessment, caveats=result.caveats, recommendations=result.recommendations,
                                         scope=ClaimScope(environment="production", services=["Supabase Storage"], regions=[project_ref]))
        envelope = self.agent.build_envelope(claims=[claim], subject=subject, relying_party=relying_party)

        print("-" * 70)
        print(envelope.summary())
        print()
        print(envelope.to_json(indent=2))

        output_path = "supabase_storage_buckets_envelope.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  Envelope saved to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OTVP Supabase Storage Bucket Policy Agent")
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    parser.add_argument("--project-ref", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if not os.environ.get("SUPABASE_DB_HOST"):
        print("ERROR: SUPABASE_DB_HOST is required.", file=sys.stderr); sys.exit(1)
    if not os.environ.get("SUPABASE_DB_PASSWORD"):
        print("ERROR: SUPABASE_DB_PASSWORD is required.", file=sys.stderr); sys.exit(1)
    agent = SupabaseStorageAgent.create(project_ref=args.project_ref)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
