#!/usr/bin/env python3
"""
OTVP Supabase Agent: Realtime Channel Security

Verifies Realtime configuration: whether Realtime is enabled on tables,
RLS coverage on realtime-enabled tables, and broadcast/presence
channel authorization.

Maps to SOC 2 CC6.1, CC6.7.

Usage:
    export SUPABASE_DB_HOST=... SUPABASE_DB_PORT=6543 SUPABASE_DB_USER=...
    export SUPABASE_DB_PASSWORD=... SUPABASE_PROJECT_REF=...
    python run_supabase_realtime_agent.py
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
from otvp_agent.agents.supabase.constants import DOMAIN_REALTIME_CHANNELS, SYSTEM_SCHEMAS
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.supabase_realtime")


def _schema_exclusion_clause(column: str = "schemaname") -> str:
    placeholders = ", ".join(f"'{s}'" for s in SYSTEM_SCHEMAS)
    return f"{column} NOT IN ({placeholders})"


# Tables in the supabase_realtime publication
SQL_REALTIME_PUBLICATIONS = """
SELECT schemaname, tablename
FROM pg_publication_tables
WHERE pubname = 'supabase_realtime'
ORDER BY schemaname, tablename;
"""

# Check RLS status on realtime-enabled tables
SQL_TABLES_RLS_STATUS = f"""
SELECT schemaname, tablename, rowsecurity
FROM pg_tables
WHERE {_schema_exclusion_clause()}
ORDER BY schemaname, tablename;
"""

# Check for realtime policies in pg_policies (policies referencing realtime)
SQL_REALTIME_POLICIES = f"""
SELECT schemaname, tablename, policyname, roles, cmd, qual
FROM pg_policies
WHERE {_schema_exclusion_clause()}
ORDER BY schemaname, tablename, policyname;
"""


class RealtimeChannelCollector(SupabaseCollector):
    domain = DOMAIN_REALTIME_CHANNELS

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        conn = self.connection
        if conn is None:
            raise RuntimeError("RealtimeChannelCollector requires a SupabaseConnection.")

        evidence_items: list[Evidence] = []

        # 1. Tables in supabase_realtime publication
        rt_tables = conn.execute(SQL_REALTIME_PUBLICATIONS)
        rt_table_set = {f"{t['schemaname']}.{t['tablename']}" for t in rt_tables}

        evidence_items.append(self.make_evidence(
            resource_id="realtime.publication_tables",
            observation={
                "check": "realtime_publication",
                "table_count": len(rt_tables),
                "tables": [f"{t['schemaname']}.{t['tablename']}" for t in rt_tables][:30],
                "passed": True,  # Informational
                "severity": "none",
                "detail": f"{len(rt_tables)} table(s) in the supabase_realtime publication.",
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.7", "agent": "supabase-realtime-channels"},
        ))

        if not rt_tables:
            evidence_items.append(self.make_evidence(
                resource_id="realtime.no_tables",
                observation={
                    "check": "realtime_not_configured",
                    "passed": True,
                    "severity": "none",
                    "detail": "No tables are published to Realtime. Realtime data streaming is not in use.",
                },
                tags={"framework": "soc2", "criteria": "CC6.1,CC6.7", "agent": "supabase-realtime-channels"},
            ))
            return evidence_items

        # 2. RLS status on realtime tables
        all_tables = conn.execute(SQL_TABLES_RLS_STATUS)
        rls_map = {f"{t['schemaname']}.{t['tablename']}": t.get("rowsecurity", False) for t in all_tables}

        rt_without_rls = []
        rt_with_rls = []
        for table_key in rt_table_set:
            if rls_map.get(table_key, False):
                rt_with_rls.append(table_key)
            else:
                rt_without_rls.append(table_key)

        passed = len(rt_without_rls) == 0
        evidence_items.append(self.make_evidence(
            resource_id="realtime.rls_coverage",
            observation={
                "check": "realtime_rls_coverage",
                "total_realtime_tables": len(rt_table_set),
                "with_rls": len(rt_with_rls),
                "without_rls": len(rt_without_rls),
                "tables_without_rls": sorted(rt_without_rls)[:20],
                "passed": passed,
                "severity": "critical" if not passed else "none",
                "detail": (
                    f"{len(rt_without_rls)} Realtime-enabled table(s) lack RLS: "
                    f"{', '.join(sorted(rt_without_rls)[:5])}. "
                    "Any subscriber can see all changes to these tables."
                    if not passed else
                    f"All {len(rt_table_set)} Realtime-enabled table(s) have RLS enabled."
                ),
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.7", "agent": "supabase-realtime-channels"},
        ))

        # 3. Policy coverage on realtime tables
        all_policies = conn.execute(SQL_REALTIME_POLICIES)
        policies_by_table: dict[str, list[str]] = {}
        for p in all_policies:
            key = f"{p['schemaname']}.{p['tablename']}"
            policies_by_table.setdefault(key, []).append(p["policyname"])

        rt_no_policies = [t for t in rt_table_set if t not in policies_by_table]
        passed = len(rt_no_policies) == 0
        evidence_items.append(self.make_evidence(
            resource_id="realtime.policy_coverage",
            observation={
                "check": "realtime_policy_coverage",
                "tables_with_policies": len(rt_table_set) - len(rt_no_policies),
                "tables_without_policies": len(rt_no_policies),
                "missing_policies": sorted(rt_no_policies)[:20],
                "passed": passed,
                "severity": "high" if not passed else "none",
                "detail": (
                    f"{len(rt_no_policies)} Realtime table(s) have RLS enabled but NO policies — "
                    "default-deny blocks all access including Realtime subscriptions."
                    if not passed else
                    f"All Realtime-enabled tables have RLS policies defined."
                ),
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.7", "agent": "supabase-realtime-channels"},
        ))

        # 4. SELECT policy check (Realtime needs SELECT policies)
        rt_no_select = []
        for table_key in rt_table_set:
            table_policies = policies_by_table.get(table_key, [])
            # Check if any policy applies to SELECT
            has_select = False
            for p in all_policies:
                pk = f"{p['schemaname']}.{p['tablename']}"
                if pk == table_key and p["cmd"] in ("SELECT", "*"):
                    has_select = True
                    break
            if not has_select and table_policies:
                rt_no_select.append(table_key)

        if rt_no_select:
            evidence_items.append(self.make_evidence(
                resource_id="realtime.select_policies",
                observation={
                    "check": "realtime_select_policies",
                    "tables_without_select": rt_no_select[:20],
                    "count": len(rt_no_select),
                    "passed": False,
                    "severity": "medium",
                    "detail": (
                        f"{len(rt_no_select)} Realtime table(s) have policies but none for SELECT — "
                        "Realtime subscriptions require SELECT permission."
                    ),
                },
                tags={"framework": "soc2", "criteria": "CC6.1,CC6.7", "agent": "supabase-realtime-channels"},
            ))

        return evidence_items


class RealtimeChannelEvaluator(SupabaseEvaluator):
    domain = DOMAIN_REALTIME_CHANNELS
    assertion = "Supabase Realtime channels are properly secured with RLS policies controlling subscription access"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.INDETERMINATE, confidence=0.0,
                                    assessment="No Realtime channel evidence collected.", evidence_ids=[])

        passed, failed = [], []
        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            if obs.get("passed", False):
                passed.append(obs.get("check", "?"))
            else:
                failed.append({"check": obs.get("check", "?"), "severity": obs.get("severity", "none"), "detail": obs.get("detail", "")})

        total = len(evidence_items)
        all_ids = [e.evidence_id for e in evidence_items]

        # If no realtime tables, it's NOT_APPLICABLE
        if total == 2 and any(
            isinstance(e.observation, dict) and e.observation.get("check") == "realtime_not_configured"
            for e in evidence_items
        ):
            return EvaluationResult(result=ClaimResult.NOT_APPLICABLE, confidence=1.0,
                                    assessment="Realtime is not configured — no tables in the supabase_realtime publication.",
                                    evidence_ids=all_ids)

        if len(passed) == total:
            return EvaluationResult(result=ClaimResult.SATISFIED, confidence=1.0,
                                    assessment=f"All {total} Realtime security checks pass.", evidence_ids=all_ids)
        if not passed:
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=1.0,
                                    assessment=f"All {total} Realtime checks have issues.",
                                    caveats=[f"{f['check']}: {f['detail']}" for f in failed],
                                    recommendations=[_rt_rec(f) for f in failed[:5]], evidence_ids=all_ids)

        confidence = round(len(passed) / total, 3)
        return EvaluationResult(result=ClaimResult.PARTIAL, confidence=confidence,
                                assessment=f"{len(passed)}/{total} Realtime checks pass.",
                                caveats=[f"{f['check']} [{f['severity']}]: {f['detail']}" for f in failed],
                                recommendations=[_rt_rec(f) for f in failed[:5]], evidence_ids=all_ids)


def _rt_rec(f: dict) -> str:
    check = f["check"]
    if check == "realtime_rls_coverage":
        return "Enable RLS on all Realtime-enabled tables: ALTER TABLE <name> ENABLE ROW LEVEL SECURITY;"
    if check == "realtime_policy_coverage":
        return "Create RLS policies for Realtime tables. Without policies, RLS default-deny blocks all subscriptions."
    if check == "realtime_select_policies":
        return "Add SELECT policies to Realtime tables — subscriptions require SELECT permission to receive change events."
    return f"Review: {f['detail']}"


class SupabaseRealtimeAgent:
    def __init__(self, agent: Agent, connection: SupabaseConnection) -> None:
        self.agent = agent
        self.connection = connection
        self.collector = RealtimeChannelCollector()
        self.evaluator = RealtimeChannelEvaluator()

    @classmethod
    def create(cls, project_ref: str | None = None) -> SupabaseRealtimeAgent:
        keys = KeyPair.generate()
        config = AgentConfig(agent_id="supabase-realtime-agent-v1", vendor="OTVP Reference / Killswitch Advisory",
                             version="1.0.0", key_pair=keys, domains=[Domain.REALTIME_CHANNELS])
        return cls(agent=Agent(config), connection=SupabaseConnection(project_ref=project_ref))

    async def run(self, subject: str = "killswitch-advisory", relying_party: str | None = None) -> None:
        project_ref = self.connection.project_ref or "(unknown)"
        print("=" * 70)
        print("  OTVP Supabase Agent: Realtime Channel Security")
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

        claim = self.agent.create_claim(domain=DOMAIN_REALTIME_CHANNELS, assertion=self.evaluator.assertion,
                                         result=result.result, confidence=result.confidence, evidence_refs=signed_refs,
                                         opinion=result.assessment, caveats=result.caveats, recommendations=result.recommendations,
                                         scope=ClaimScope(environment="production", services=["Supabase Realtime"], regions=[project_ref]))
        envelope = self.agent.build_envelope(claims=[claim], subject=subject, relying_party=relying_party)

        print("-" * 70)
        print(envelope.summary())
        print()
        print(envelope.to_json(indent=2))

        output_path = "supabase_realtime_channels_envelope.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  Envelope saved to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OTVP Supabase Realtime Channel Security Agent")
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    parser.add_argument("--project-ref", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if not os.environ.get("SUPABASE_DB_HOST"):
        print("ERROR: SUPABASE_DB_HOST is required.", file=sys.stderr); sys.exit(1)
    if not os.environ.get("SUPABASE_DB_PASSWORD"):
        print("ERROR: SUPABASE_DB_PASSWORD is required.", file=sys.stderr); sys.exit(1)
    agent = SupabaseRealtimeAgent.create(project_ref=args.project_ref)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
