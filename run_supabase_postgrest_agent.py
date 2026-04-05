#!/usr/bin/env python3
"""
OTVP Supabase Agent: PostgREST Exposure

Identifies tables, views, and functions exposed via the REST/GraphQL API,
with focus on SECURITY DEFINER functions (bypass RLS) and views without
security_invoker (may leak data).

Maps to SOC 2 CC6.1, CC6.6.

Usage:
    export SUPABASE_DB_HOST=... SUPABASE_DB_PORT=6543 SUPABASE_DB_USER=...
    export SUPABASE_DB_PASSWORD=... SUPABASE_PROJECT_REF=...
    python run_supabase_postgrest_agent.py
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
from otvp_agent.agents.supabase.constants import DOMAIN_POSTGREST_EXPOSURE, SYSTEM_SCHEMAS
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.supabase_postgrest")


def _schema_exclusion_clause(column: str = "n.nspname") -> str:
    placeholders = ", ".join(f"'{s}'" for s in SYSTEM_SCHEMAS)
    return f"{column} NOT IN ({placeholders})"


SQL_SECURITY_DEFINER_FUNCTIONS = f"""
SELECT n.nspname AS schema_name, p.proname AS function_name,
       pg_get_function_identity_arguments(p.oid) AS args,
       p.prosecdef AS is_security_definer,
       l.lanname AS language
FROM pg_proc p
JOIN pg_namespace n ON p.pronamespace = n.oid
JOIN pg_language l ON p.prolang = l.oid
WHERE p.prosecdef = true
AND {_schema_exclusion_clause()}
ORDER BY n.nspname, p.proname;
"""

SQL_VIEWS_WITHOUT_SECURITY_INVOKER = f"""
SELECT n.nspname AS schema_name, c.relname AS view_name,
       pg_get_viewdef(c.oid, true) AS view_definition
FROM pg_class c
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE c.relkind = 'v'
AND {_schema_exclusion_clause()}
ORDER BY n.nspname, c.relname;
"""

SQL_EXPOSED_FUNCTIONS = f"""
SELECT n.nspname AS schema_name, p.proname AS function_name,
       pg_get_function_identity_arguments(p.oid) AS args,
       p.prosecdef AS is_security_definer,
       p.provolatile AS volatility,
       l.lanname AS language
FROM pg_proc p
JOIN pg_namespace n ON p.pronamespace = n.oid
JOIN pg_language l ON p.prolang = l.oid
WHERE {_schema_exclusion_clause()}
AND l.lanname NOT IN ('internal', 'c')
ORDER BY n.nspname, p.proname;
"""


class PostgRESTCollector(SupabaseCollector):
    domain = DOMAIN_POSTGREST_EXPOSURE

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        conn = self.connection
        if conn is None:
            raise RuntimeError("PostgRESTCollector requires a SupabaseConnection.")

        evidence_items: list[Evidence] = []
        project_ref = conn.project_ref

        # 1. SECURITY DEFINER functions in exposed schemas
        sec_def_funcs = conn.execute(SQL_SECURITY_DEFINER_FUNCTIONS)
        passed = len(sec_def_funcs) == 0
        evidence_items.append(self.make_evidence(
            resource_id="postgrest.security_definer_functions",
            observation={
                "check": "security_definer_functions",
                "count": len(sec_def_funcs),
                "functions": [
                    {"schema": f["schema_name"], "name": f["function_name"],
                     "args": f["args"], "language": f["language"]}
                    for f in sec_def_funcs
                ],
                "passed": passed,
                "severity": "high" if not passed else "none",
                "detail": (
                    f"{len(sec_def_funcs)} SECURITY DEFINER function(s) in exposed schemas — "
                    "these bypass RLS and run with the function owner's privileges."
                    if not passed else
                    "No SECURITY DEFINER functions found in exposed schemas."
                ),
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.6", "agent": "supabase-postgrest-exposure"},
        ))

        # 2. Views without security_invoker
        views = conn.execute(SQL_VIEWS_WITHOUT_SECURITY_INVOKER)
        views_without_invoker = []
        for v in views:
            defn = v.get("view_definition", "") or ""
            # security_invoker = true is set as a view option
            # If not present, the view runs as the view owner (not the caller)
            has_security_invoker = "security_invoker" in defn.lower()
            if not has_security_invoker:
                views_without_invoker.append({
                    "schema": v["schema_name"],
                    "name": v["view_name"],
                })

        passed = len(views_without_invoker) == 0
        evidence_items.append(self.make_evidence(
            resource_id="postgrest.views_security_invoker",
            observation={
                "check": "views_without_security_invoker",
                "total_views": len(views),
                "without_security_invoker": len(views_without_invoker),
                "views": views_without_invoker[:20],
                "passed": passed,
                "severity": "medium" if not passed else "none",
                "detail": (
                    f"{len(views_without_invoker)}/{len(views)} view(s) lack security_invoker = true — "
                    "they run as the view owner and may expose data that RLS would normally filter."
                    if not passed else
                    f"All {len(views)} view(s) have security_invoker set or no views found."
                ),
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.6", "agent": "supabase-postgrest-exposure"},
        ))

        # 3. Exposed function inventory
        all_funcs = conn.execute(SQL_EXPOSED_FUNCTIONS)
        evidence_items.append(self.make_evidence(
            resource_id="postgrest.exposed_functions",
            observation={
                "check": "exposed_function_inventory",
                "total_functions": len(all_funcs),
                "security_definer_count": sum(1 for f in all_funcs if f.get("is_security_definer")),
                "by_language": _count_by(all_funcs, "language"),
                "passed": True,
                "severity": "none",
                "detail": f"{len(all_funcs)} function(s) in exposed schemas.",
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.6", "agent": "supabase-postgrest-exposure"},
        ))

        return evidence_items


def _count_by(rows: list[dict], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in rows:
        val = str(r.get(key, "unknown"))
        counts[val] = counts.get(val, 0) + 1
    return counts


class PostgRESTEvaluator(SupabaseEvaluator):
    domain = DOMAIN_POSTGREST_EXPOSURE
    assertion = "PostgREST-exposed objects follow least-privilege principles with no unsafe SECURITY DEFINER functions or unprotected views"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.INDETERMINATE, confidence=0.0,
                                    assessment="No PostgREST exposure evidence collected.", evidence_ids=[])

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
                                    assessment=f"All {total} PostgREST exposure checks pass.", evidence_ids=all_ids)
        if not passed:
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=1.0,
                                    assessment=f"All {total} checks have issues.",
                                    caveats=[f"{f['check']}: {f['detail']}" for f in failed],
                                    recommendations=[_postgrest_rec(f) for f in failed[:5]], evidence_ids=all_ids)

        confidence = round(len(passed) / total, 3)
        return EvaluationResult(result=ClaimResult.PARTIAL, confidence=confidence,
                                assessment=f"{len(passed)}/{total} PostgREST checks pass.",
                                caveats=[f"{f['check']} [{f['severity']}]: {f['detail']}" for f in failed],
                                recommendations=[_postgrest_rec(f) for f in failed[:5]], evidence_ids=all_ids)


def _postgrest_rec(f: dict) -> str:
    if f["check"] == "security_definer_functions":
        return "Convert SECURITY DEFINER functions to SECURITY INVOKER where possible, or move them to a non-exposed schema."
    if f["check"] == "views_without_security_invoker":
        return "Add 'security_invoker = true' to views in exposed schemas: ALTER VIEW <name> SET (security_invoker = true);"
    return f"Review: {f['detail']}"


class SupabasePostgRESTAgent:
    def __init__(self, agent: Agent, connection: SupabaseConnection) -> None:
        self.agent = agent
        self.connection = connection
        self.collector = PostgRESTCollector()
        self.evaluator = PostgRESTEvaluator()

    @classmethod
    def create(cls, project_ref: str | None = None) -> SupabasePostgRESTAgent:
        keys = KeyPair.generate()
        config = AgentConfig(agent_id="supabase-postgrest-agent-v1", vendor="OTVP Reference / Killswitch Advisory",
                             version="1.0.0", key_pair=keys, domains=[Domain.POSTGREST_EXPOSURE])
        return cls(agent=Agent(config), connection=SupabaseConnection(project_ref=project_ref))

    async def run(self, subject: str = "killswitch-advisory", relying_party: str | None = None) -> None:
        project_ref = self.connection.project_ref or "(unknown)"
        print("=" * 70)
        print("  OTVP Supabase Agent: PostgREST Exposure")
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

        claim = self.agent.create_claim(domain=DOMAIN_POSTGREST_EXPOSURE, assertion=self.evaluator.assertion,
                                         result=result.result, confidence=result.confidence, evidence_refs=signed_refs,
                                         opinion=result.assessment, caveats=result.caveats, recommendations=result.recommendations,
                                         scope=ClaimScope(environment="production", services=["Supabase PostgREST"], regions=[project_ref]))
        envelope = self.agent.build_envelope(claims=[claim], subject=subject, relying_party=relying_party)

        print("-" * 70)
        print(envelope.summary())
        print()
        print(envelope.to_json(indent=2))

        output_path = "supabase_postgrest_exposure_envelope.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  Envelope saved to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OTVP Supabase PostgREST Exposure Agent")
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    parser.add_argument("--project-ref", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if not os.environ.get("SUPABASE_DB_HOST"):
        print("ERROR: SUPABASE_DB_HOST is required.", file=sys.stderr); sys.exit(1)
    if not os.environ.get("SUPABASE_DB_PASSWORD"):
        print("ERROR: SUPABASE_DB_PASSWORD is required.", file=sys.stderr); sys.exit(1)
    agent = SupabasePostgRESTAgent.create(project_ref=args.project_ref)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
