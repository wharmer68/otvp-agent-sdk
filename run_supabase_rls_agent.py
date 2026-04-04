#!/usr/bin/env python3
"""
OTVP Supabase Agent: RLS Enforcement

Verifies that every table exposed to the Supabase Data API has Row-Level
Security (RLS) enabled with at least one effective policy.  This is the #1
misconfiguration on Supabase and the most critical security control customers
own.

Maps to SOC 2 CC6.1 (Logical Access Security), CC6.3 (Role-Based Access).

Usage:
    export SUPABASE_DB_HOST=db.<project-ref>.supabase.co
    export SUPABASE_DB_PASSWORD=<your-db-password>
    export SUPABASE_PROJECT_REF=<project-ref>
    python run_supabase_rls_agent.py
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
    DOMAIN_RLS,
    SUPABASE_API_ROLES,
    SYSTEM_SCHEMAS,
)
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.supabase_rls")


# ── SQL Queries ────────────────────────────────────────────────────

def _schema_exclusion_clause(column: str = "schemaname") -> str:
    """Build a SQL WHERE exclusion for Supabase system schemas."""
    placeholders = ", ".join(f"'{s}'" for s in SYSTEM_SCHEMAS)
    return f"{column} NOT IN ({placeholders})"


SQL_TABLES = f"""
SELECT schemaname, tablename, rowsecurity
FROM pg_tables
WHERE {_schema_exclusion_clause()}
ORDER BY schemaname, tablename;
"""

SQL_POLICIES = f"""
SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
FROM pg_policies
WHERE {_schema_exclusion_clause()}
ORDER BY schemaname, tablename, policyname;
"""

SQL_GRANTS = f"""
SELECT table_schema, table_name, grantee, privilege_type
FROM information_schema.table_privileges
WHERE grantee IN ('anon', 'authenticated', 'service_role')
AND {_schema_exclusion_clause("table_schema")}
ORDER BY table_schema, table_name, grantee;
"""


# ── Helpers ────────────────────────────────────────────────────────

def _is_using_true(expression: str | None) -> bool:
    """Check if a USING or WITH CHECK expression is effectively ``true``."""
    if expression is None:
        return False
    normalized = expression.strip().lower().replace("(", "").replace(")", "").strip()
    return normalized == "true"


def _parse_roles(roles: str | list | None) -> list[str]:
    """Normalize the ``roles`` column from pg_policies into a list."""
    if roles is None:
        return []
    if isinstance(roles, list):
        return [str(r) for r in roles]
    # pg_policies returns roles as a Postgres array literal, e.g. "{anon,authenticated}"
    cleaned = str(roles).strip("{}")
    return [r.strip() for r in cleaned.split(",") if r.strip()]


# ── Collector ──────────────────────────────────────────────────────


class RLSCollector(SupabaseCollector):
    """Collects RLS status, policies, and grants for all exposed tables."""

    domain = DOMAIN_RLS

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        conn = self.connection
        if conn is None:
            raise RuntimeError("RLSCollector requires a SupabaseConnection.")

        # 1. Fetch all user-schema tables
        tables = conn.execute(SQL_TABLES)

        # 2. Fetch all RLS policies
        policies_raw = conn.execute(SQL_POLICIES)

        # 3. Fetch table grants for API roles
        grants_raw = conn.execute(SQL_GRANTS)

        # ── Index policies by schema.table ─────────────────────────
        policies_by_table: dict[str, list[dict]] = {}
        for row in policies_raw:
            key = f"{row['schemaname']}.{row['tablename']}"
            parsed_roles = _parse_roles(row.get("roles"))
            policy_info = {
                "name": row["policyname"],
                "permissive": row.get("permissive", "PERMISSIVE"),
                "roles": parsed_roles,
                "command": row.get("cmd", "ALL"),
                "has_using_true": _is_using_true(row.get("qual")),
                "has_check_true": _is_using_true(row.get("with_check")),
            }
            policies_by_table.setdefault(key, []).append(policy_info)

        # ── Index grants by schema.table ───────────────────────────
        grants_by_table: dict[str, dict[str, list[str]]] = {}
        for row in grants_raw:
            key = f"{row['table_schema']}.{row['table_name']}"
            grantee = row["grantee"]
            priv = row["privilege_type"]
            grants_by_table.setdefault(key, {}).setdefault(grantee, []).append(priv)

        # ── Build one Evidence item per table ──────────────────────
        evidence_items: list[Evidence] = []
        project_ref = conn.project_ref

        for tbl in tables:
            schema = tbl["schemaname"]
            table_name = tbl["tablename"]
            resource_id = f"{schema}.{table_name}"
            rls_enabled = bool(tbl.get("rowsecurity", False))

            table_policies = policies_by_table.get(resource_id, [])
            table_grants = grants_by_table.get(resource_id, {})

            # Determine risk flags
            risk_flags: list[str] = []
            if not rls_enabled:
                risk_flags.append("rls_disabled")
            elif len(table_policies) == 0:
                risk_flags.append("no_policies")

            # Check for dangerous USING(true) patterns on public roles
            for pol in table_policies:
                if pol["has_using_true"]:
                    affected_roles = pol["roles"]
                    if "anon" in affected_roles or not affected_roles:
                        risk_flags.append("using_true_on_anon")
                    elif "authenticated" in affected_roles:
                        risk_flags.append("using_true_on_authenticated")
                if pol["has_check_true"]:
                    risk_flags.append("with_check_true")

            # Check for grants without RLS protection
            has_api_grants = any(
                role in table_grants for role in SUPABASE_API_ROLES
            )
            if has_api_grants and not rls_enabled:
                risk_flags.append("exposed_without_rls")

            # Quick compliance determination
            compliant = (
                rls_enabled
                and len(table_policies) > 0
                and "using_true_on_anon" not in risk_flags
            )

            evidence_items.append(
                self.make_evidence(
                    resource_id=resource_id,
                    observation={
                        "table_schema": schema,
                        "table_name": table_name,
                        "rls_enabled": rls_enabled,
                        "rls_forced": rls_enabled,  # rowsecurity = FORCE ROW LEVEL SECURITY
                        "policy_count": len(table_policies),
                        "policies": table_policies,
                        "grants": table_grants,
                        "risk_flags": risk_flags,
                        "compliant": compliant,
                    },
                    tags={
                        "framework": "soc2",
                        "criteria": "CC6.1,CC6.3",
                        "agent": "supabase-rls-enforcement",
                    },
                )
            )

        return evidence_items


# ── Evaluator ──────────────────────────────────────────────────────


class RLSEvaluator(SupabaseEvaluator):
    """Evaluates whether all exposed tables have effective RLS."""

    domain = DOMAIN_RLS
    assertion = "All tables exposed to the Supabase Data API have Row Level Security enabled with effective policies"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(
                result=ClaimResult.NOT_APPLICABLE,
                confidence=1.0,
                assessment="No tables found in exposed schemas. Nothing to verify.",
                evidence_ids=[],
            )

        compliant_tables: list[str] = []
        partial_tables: list[dict] = []   # Overly permissive but RLS is on
        non_compliant_tables: list[dict] = []  # RLS off or no policies
        risk_findings: list[dict] = []

        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            schema = obs.get("table_schema", "?")
            table = obs.get("table_name", "?")
            resource_id = f"{schema}.{table}"
            rls_enabled = obs.get("rls_enabled", False)
            policy_count = obs.get("policy_count", 0)
            risk_flags = obs.get("risk_flags", [])

            if not rls_enabled:
                # Critical: RLS not enabled
                non_compliant_tables.append({
                    "table": resource_id,
                    "reason": "RLS disabled",
                })
                risk_findings.append({
                    "table": resource_id,
                    "risk": "rls_disabled",
                    "severity": "critical",
                    "recommendation": f"Enable RLS: ALTER TABLE {resource_id} ENABLE ROW LEVEL SECURITY;",
                })
            elif policy_count == 0:
                # RLS on but no policies = all access blocked, likely misconfiguration
                non_compliant_tables.append({
                    "table": resource_id,
                    "reason": "RLS enabled but no policies defined",
                })
                risk_findings.append({
                    "table": resource_id,
                    "risk": "no_policies",
                    "severity": "high",
                    "recommendation": (
                        f"Add RLS policies to {resource_id}. "
                        "RLS is enabled but without policies all access is blocked, "
                        "which may indicate a misconfiguration."
                    ),
                })
            elif "using_true_on_anon" in risk_flags:
                # Overly permissive — USING(true) on anon role
                # RLS is on and policies exist, but they're too open
                partial_tables.append({
                    "table": resource_id,
                    "reason": "Overly permissive: USING(true) on anon role",
                })
                risk_findings.append({
                    "table": resource_id,
                    "risk": "using_true_on_anon",
                    "severity": "high",
                    "recommendation": (
                        f"Replace USING (true) with a proper filter on {resource_id} "
                        "for the anon role. USING (true) effectively disables RLS "
                        "for unauthenticated users."
                    ),
                })
            else:
                # Compliant
                compliant_tables.append(resource_id)

        total = len(evidence_items)
        pass_count = len(compliant_tables)
        partial_count = len(partial_tables)
        fail_count = len(non_compliant_tables)

        details = {
            "total_tables": total,
            "rls_enabled_count": sum(
                1 for e in evidence_items
                if isinstance(e.observation, dict) and e.observation.get("rls_enabled")
            ),
            "rls_disabled_count": sum(
                1 for e in evidence_items
                if isinstance(e.observation, dict) and not e.observation.get("rls_enabled")
            ),
            "tables_with_policies": sum(
                1 for e in evidence_items
                if isinstance(e.observation, dict) and e.observation.get("policy_count", 0) > 0
            ),
            "tables_without_policies": sum(
                1 for e in evidence_items
                if isinstance(e.observation, dict) and e.observation.get("policy_count", 0) == 0
            ),
            "compliant_tables": compliant_tables,
            "partial_tables": partial_tables,
            "non_compliant_tables": non_compliant_tables,
            "risk_findings": risk_findings,
        }

        all_evidence_ids = [e.evidence_id for e in evidence_items]

        # Determine aggregate result
        if pass_count == total:
            return EvaluationResult(
                result=ClaimResult.SATISFIED,
                confidence=1.0,
                assessment=(
                    f"All {total} table(s) in exposed schemas have RLS enabled "
                    "with effective policies. 100% of population verified."
                ),
                evidence_ids=all_evidence_ids,
            )

        # Any non-compliant tables (RLS off or no policies) = NOT_SATISFIED
        # unless some tables are compliant, then PARTIAL
        if fail_count > 0 and pass_count == 0 and partial_count == 0:
            recommendations = []
            for finding in risk_findings[:5]:
                recommendations.append(finding["recommendation"])

            return EvaluationResult(
                result=ClaimResult.NOT_SATISFIED,
                confidence=1.0,
                assessment=(
                    f"No tables pass RLS verification (0/{total}). "
                    f"{details['rls_disabled_count']} table(s) have RLS disabled."
                ),
                caveats=[
                    f"Non-compliant tables: {', '.join(t['table'] for t in non_compliant_tables[:10])}"
                ],
                recommendations=recommendations,
                evidence_ids=all_evidence_ids,
            )

        # Partial compliance — mix of compliant, partial, and/or non-compliant
        # Confidence = fully compliant / total (direct ratio)
        confidence = round(pass_count / total, 3)
        caveats = []
        for entry in non_compliant_tables[:10]:
            caveats.append(f"{entry['table']}: {entry['reason']}")
        for entry in partial_tables[:10]:
            caveats.append(f"{entry['table']}: {entry['reason']}")

        recommendations = []
        for finding in risk_findings[:5]:
            recommendations.append(finding["recommendation"])

        issue_count = fail_count + partial_count
        return EvaluationResult(
            result=ClaimResult.PARTIAL,
            confidence=confidence,
            assessment=(
                f"{pass_count}/{total} table(s) fully pass RLS verification. "
                f"{issue_count} table(s) have issues "
                f"({fail_count} non-compliant, {partial_count} overly permissive)."
            ),
            caveats=caveats,
            recommendations=recommendations,
            evidence_ids=all_evidence_ids,
        )


# ── Composite Agent ────────────────────────────────────────────────


class SupabaseRLSAgent:
    """Orchestrates RLS enforcement verification for a Supabase project."""

    def __init__(self, agent: Agent, connection: SupabaseConnection) -> None:
        self.agent = agent
        self.connection = connection
        self.collector = RLSCollector()
        self.evaluator = RLSEvaluator()

    @classmethod
    def create(
        cls,
        project_ref: str | None = None,
        host: str | None = None,
        password: str | None = None,
    ) -> SupabaseRLSAgent:
        keys = KeyPair.generate()
        config = AgentConfig(
            agent_id="supabase-rls-agent-v1",
            vendor="OTVP Reference / Killswitch Advisory",
            version="1.0.0",
            key_pair=keys,
            domains=[Domain.ROW_LEVEL_SECURITY],
        )
        agent = Agent(config)
        connection = SupabaseConnection(
            host=host,
            password=password,
            project_ref=project_ref,
        )
        return cls(agent=agent, connection=connection)

    async def run(
        self,
        subject: str = "killswitch-advisory",
        relying_party: str | None = None,
    ) -> None:
        project_ref = self.connection.project_ref or "(unknown)"

        print("=" * 70)
        print("  OTVP Supabase Agent: RLS Enforcement")
        print(f"  Project: {project_ref}")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        # 1. Connect and collect
        with self.connection as conn:
            self.collector.connection = conn
            ctx = CollectionContext(
                environment="production",
                custom={"project_ref": project_ref},
            )
            evidence = await self.collector.collect(ctx)

        print(f"  Collected {len(evidence)} table evidence items")
        if evidence:
            rls_on = sum(
                1 for e in evidence
                if isinstance(e.observation, dict) and e.observation.get("rls_enabled")
            )
            print(f"    Tables with RLS enabled:  {rls_on}")
            print(f"    Tables with RLS disabled: {len(evidence) - rls_on}")
        print()

        # 2. Sign and store evidence
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
                print(f"  ! Caveat: {c}")
        if result.recommendations:
            for r in result.recommendations:
                print(f"  > Recommendation: {r}")
        print()

        # 4. Create signed claim
        claim = self.agent.create_claim(
            domain=DOMAIN_RLS,
            assertion=self.evaluator.assertion,
            result=result.result,
            confidence=result.confidence,
            evidence_refs=signed_refs,
            opinion=result.assessment,
            caveats=result.caveats,
            recommendations=result.recommendations,
            scope=ClaimScope(
                environment="production",
                services=["Supabase PostgreSQL"],
                regions=[project_ref],
            ),
        )

        # 5. Build envelope
        envelope = self.agent.build_envelope(
            claims=[claim],
            subject=subject,
            relying_party=relying_party,
        )

        # 6. Summary
        print("-" * 70)
        print(envelope.summary())
        print()

        # 7. Verification
        print("-" * 70)
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
        print("-" * 70)
        print("Full Trust Envelope (JSON):")
        print("-" * 70)
        print(envelope.to_json(indent=2))

        # 9. Save
        output_path = "supabase_rls_enforcement_envelope.json"
        with open(output_path, "w") as f:
            f.write(envelope.to_json(indent=2))
        print(f"\n  Envelope saved to: {output_path}")


# ── CLI ────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OTVP Supabase RLS Enforcement Agent",
    )
    parser.add_argument(
        "--subject",
        default="killswitch-advisory",
        help="Subject organization name (default: killswitch-advisory)",
    )
    parser.add_argument(
        "--relying-party",
        default=None,
        help="Relying party organization name",
    )
    parser.add_argument(
        "--project-ref",
        default=None,
        help="Supabase project reference (overrides SUPABASE_PROJECT_REF env var)",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Validate required env vars
    host = os.environ.get("SUPABASE_DB_HOST", "")
    password = os.environ.get("SUPABASE_DB_PASSWORD", "")
    if not host:
        print("ERROR: SUPABASE_DB_HOST environment variable is required.", file=sys.stderr)
        print("  Set it to: db.<project-ref>.supabase.co", file=sys.stderr)
        sys.exit(1)
    if not password:
        print("ERROR: SUPABASE_DB_PASSWORD environment variable is required.", file=sys.stderr)
        sys.exit(1)

    agent = SupabaseRLSAgent.create(
        project_ref=args.project_ref,
    )
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))


if __name__ == "__main__":
    main()
