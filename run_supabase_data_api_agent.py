#!/usr/bin/env python3
"""
OTVP Supabase Agent: Data API Hardening

Verifies that the Supabase Data API surface is minimized and secured:
exposed schemas, table-level privileges per role, and whether an event
trigger exists to auto-enable RLS on new tables.

Maps to SOC 2 CC6.1, CC6.6, CC6.7.

Usage:
    export SUPABASE_DB_HOST=aws-0-us-east-1.pooler.supabase.com
    export SUPABASE_DB_PORT=6543
    export SUPABASE_DB_USER=postgres.<project-ref>
    export SUPABASE_DB_PASSWORD=<your-db-password>
    export SUPABASE_PROJECT_REF=<project-ref>
    python run_supabase_data_api_agent.py
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
from otvp_agent.agents.supabase.constants import (
    DOMAIN_DATA_API_HARDENING,
    SUPABASE_API_ROLES,
    SYSTEM_SCHEMAS,
)
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.supabase_data_api")


def _schema_exclusion_clause(column: str = "schemaname") -> str:
    placeholders = ", ".join(f"'{s}'" for s in SYSTEM_SCHEMAS)
    return f"{column} NOT IN ({placeholders})"


SQL_EXPOSED_SCHEMAS = """
SELECT nspname AS schema_name
FROM pg_namespace
WHERE nspname NOT LIKE 'pg_%'
AND nspname NOT IN ('information_schema')
ORDER BY nspname;
"""

SQL_EVENT_TRIGGERS = """
SELECT evtname, evtevent, evtfoid::regproc AS function_name, evtenabled
FROM pg_event_trigger
ORDER BY evtname;
"""

SQL_TABLE_PRIVILEGES = f"""
SELECT table_schema, table_name, grantee, privilege_type
FROM information_schema.table_privileges
WHERE grantee IN ('anon', 'authenticated', 'service_role')
AND {_schema_exclusion_clause("table_schema")}
ORDER BY table_schema, table_name, grantee;
"""

SQL_TABLES_WITHOUT_RLS = f"""
SELECT schemaname, tablename, rowsecurity
FROM pg_tables
WHERE {_schema_exclusion_clause()}
AND NOT rowsecurity
ORDER BY schemaname, tablename;
"""


class DataAPICollector(SupabaseCollector):
    domain = DOMAIN_DATA_API_HARDENING

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        conn = self.connection
        if conn is None:
            raise RuntimeError("DataAPICollector requires a SupabaseConnection.")

        evidence_items: list[Evidence] = []
        project_ref = conn.project_ref

        # 1. Schemas visible (not system)
        schemas = conn.execute(SQL_EXPOSED_SCHEMAS)
        user_schemas = [
            s["schema_name"] for s in schemas
            if s["schema_name"] not in SYSTEM_SCHEMAS
        ]

        evidence_items.append(self.make_evidence(
            resource_id="api.exposed_schemas",
            observation={
                "check": "exposed_schemas",
                "schemas": user_schemas,
                "count": len(user_schemas),
                "passed": True,
                "severity": "none",
                "detail": f"{len(user_schemas)} user schema(s) visible: {', '.join(user_schemas)}.",
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.6,CC6.7", "agent": "supabase-data-api-hardening"},
        ))

        # 2. Event triggers (check for auto-RLS trigger)
        triggers = conn.execute(SQL_EVENT_TRIGGERS)
        rls_triggers = [
            t for t in triggers
            if "rls" in t.get("evtname", "").lower()
            or "rls" in str(t.get("function_name", "")).lower()
            or "row_level" in t.get("evtname", "").lower()
        ]
        has_auto_rls = len(rls_triggers) > 0

        evidence_items.append(self.make_evidence(
            resource_id="api.event_triggers",
            observation={
                "check": "auto_rls_trigger",
                "total_event_triggers": len(triggers),
                "rls_triggers": [{"name": t["evtname"], "event": t["evtevent"], "enabled": t["evtenabled"]} for t in rls_triggers],
                "has_auto_rls_trigger": has_auto_rls,
                "passed": has_auto_rls,
                "severity": "medium" if not has_auto_rls else "none",
                "detail": (
                    f"Found {len(rls_triggers)} event trigger(s) for auto-enabling RLS on new tables."
                    if has_auto_rls else
                    "No event trigger found to auto-enable RLS on new tables. "
                    "New tables will be created without RLS by default."
                ),
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.6", "agent": "supabase-data-api-hardening"},
        ))

        # 3. Table privileges per API role
        grants = conn.execute(SQL_TABLE_PRIVILEGES)
        grants_by_role: dict[str, list[str]] = {}
        for g in grants:
            role = g["grantee"]
            table = f"{g['table_schema']}.{g['table_name']}"
            grants_by_role.setdefault(role, [])
            if table not in grants_by_role[role]:
                grants_by_role[role].append(table)

        for role in SUPABASE_API_ROLES:
            tables = grants_by_role.get(role, [])
            evidence_items.append(self.make_evidence(
                resource_id=f"api.grants.{role}",
                observation={
                    "check": f"role_grants_{role}",
                    "role": role,
                    "table_count": len(tables),
                    "tables": tables[:50],
                    "passed": True,
                    "severity": "none",
                    "detail": f"Role '{role}' has grants on {len(tables)} table(s).",
                },
                tags={"framework": "soc2", "criteria": "CC6.1,CC6.6", "agent": "supabase-data-api-hardening"},
            ))

        # 4. Tables without RLS that have API grants
        no_rls = conn.execute(SQL_TABLES_WITHOUT_RLS)
        granted_tables = set()
        for tables in grants_by_role.values():
            granted_tables.update(tables)

        exposed_no_rls = [
            f"{t['schemaname']}.{t['tablename']}" for t in no_rls
            if f"{t['schemaname']}.{t['tablename']}" in granted_tables
        ]

        passed = len(exposed_no_rls) == 0
        evidence_items.append(self.make_evidence(
            resource_id="api.exposed_without_rls",
            observation={
                "check": "exposed_without_rls",
                "tables": exposed_no_rls,
                "count": len(exposed_no_rls),
                "passed": passed,
                "severity": "critical" if not passed else "none",
                "detail": (
                    f"{len(exposed_no_rls)} table(s) are accessible via API roles but have RLS disabled: "
                    f"{', '.join(exposed_no_rls[:10])}"
                    if not passed else
                    "All tables with API role grants have RLS enabled."
                ),
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.6,CC6.7", "agent": "supabase-data-api-hardening"},
        ))

        return evidence_items


class DataAPIEvaluator(SupabaseEvaluator):
    domain = DOMAIN_DATA_API_HARDENING
    assertion = "The Supabase Data API surface is hardened with appropriate access controls and RLS enforcement"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.INDETERMINATE, confidence=0.0,
                                    assessment="No Data API evidence collected.", evidence_ids=[])

        passed, failed = [], []
        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            check = obs.get("check", "?")
            if obs.get("passed", False):
                passed.append(check)
            else:
                failed.append({"check": check, "severity": obs.get("severity", "none"), "detail": obs.get("detail", "")})

        total = len(evidence_items)
        all_ids = [e.evidence_id for e in evidence_items]

        if len(passed) == total:
            return EvaluationResult(result=ClaimResult.SATISFIED, confidence=1.0,
                                    assessment=f"All {total} Data API hardening checks pass.", evidence_ids=all_ids)
        if not passed:
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=1.0,
                                    assessment=f"All {total} checks have issues.",
                                    caveats=[f"{f['check']}: {f['detail']}" for f in failed[:10]],
                                    recommendations=[_data_api_rec(f) for f in failed[:5]], evidence_ids=all_ids)

        confidence = round(len(passed) / total, 3)
        return EvaluationResult(result=ClaimResult.PARTIAL, confidence=confidence,
                                assessment=f"{len(passed)}/{total} Data API checks pass.",
                                caveats=[f"{f['check']} [{f['severity']}]: {f['detail']}" for f in failed[:10]],
                                recommendations=[_data_api_rec(f) for f in failed[:5]], evidence_ids=all_ids)


def _data_api_rec(f: dict) -> str:
    check = f["check"]
    if check == "auto_rls_trigger":
        return "Create an event trigger to auto-enable RLS on new tables: CREATE EVENT TRIGGER ... ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION ..."
    if check == "exposed_without_rls":
        return "Enable RLS on all tables accessible via API roles. Tables without RLS are fully exposed through the Data API."
    return f"Review: {f['detail']}"


class SupabaseDataAPIAgent:
    def __init__(self, agent: Agent, connection: SupabaseConnection) -> None:
        self.agent = agent
        self.connection = connection
        self.collector = DataAPICollector()
        self.evaluator = DataAPIEvaluator()

    @classmethod
    def create(cls, project_ref: str | None = None) -> SupabaseDataAPIAgent:
        keys = KeyPair.generate()
        config = AgentConfig(agent_id="supabase-data-api-agent-v1", vendor="OTVP Reference / Killswitch Advisory",
                             version="1.0.0", key_pair=keys, domains=[Domain.DATA_API_HARDENING])
        return cls(agent=Agent(config), connection=SupabaseConnection(project_ref=project_ref))

    async def run(self, subject: str = "killswitch-advisory", relying_party: str | None = None) -> None:
        project_ref = self.connection.project_ref or "(unknown)"
        print("=" * 70)
        print("  OTVP Supabase Agent: Data API Hardening")
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

        claim = self.agent.create_claim(domain=DOMAIN_DATA_API_HARDENING, assertion=self.evaluator.assertion,
                                         result=result.result, confidence=result.confidence, evidence_refs=signed_refs,
                                         opinion=result.assessment, caveats=result.caveats, recommendations=result.recommendations,
                                         scope=ClaimScope(environment="production", services=["Supabase Data API"], regions=[project_ref]))
        envelope = self.agent.build_envelope(claims=[claim], subject=subject, relying_party=relying_party)

        print("-" * 70)
        print(envelope.summary())
        print()
        print("-" * 70)
        print("Verification:")
        print(f"  Envelope signature valid: {self.agent.verify_envelope(envelope)}")
        for c in envelope.claims: print(f"  Claim [{c.claim_id}] valid: {self.agent.verify_claim(c)}")
        print(f"  Evidence store: {self.agent.evidence_store.size} items, root: {self.agent.evidence_store.root_hash}")
        print()
        print(envelope.to_json(indent=2))

        output_path = "supabase_data_api_hardening_envelope.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  Envelope saved to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OTVP Supabase Data API Hardening Agent")
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    parser.add_argument("--project-ref", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if not os.environ.get("SUPABASE_DB_HOST"):
        print("ERROR: SUPABASE_DB_HOST is required.", file=sys.stderr); sys.exit(1)
    if not os.environ.get("SUPABASE_DB_PASSWORD"):
        print("ERROR: SUPABASE_DB_PASSWORD is required.", file=sys.stderr); sys.exit(1)
    agent = SupabaseDataAPIAgent.create(project_ref=args.project_ref)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
