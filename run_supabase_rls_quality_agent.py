#!/usr/bin/env python3
"""
OTVP Supabase Agent: RLS Policy Quality

Goes beyond "is RLS enabled" to inspect policy definitions for anti-patterns
that weaken access control even when RLS is turned on.  Catches the most common
Supabase security mistakes: USING(true) on sensitive tables, missing auth
checks, user-modifiable metadata in security decisions, and incomplete
command coverage.

Maps to SOC 2 CC6.1 (Logical Access Security), CC6.3 (Role-Based Access).

Usage:
    export SUPABASE_DB_HOST=aws-0-us-east-1.pooler.supabase.com
    export SUPABASE_DB_PORT=6543
    export SUPABASE_DB_USER=postgres.<project-ref>
    export SUPABASE_DB_PASSWORD=<your-db-password>
    export SUPABASE_PROJECT_REF=<project-ref>
    python run_supabase_rls_quality_agent.py
"""
from __future__ import annotations

import asyncio
import argparse
import logging
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from otvp_agent import Agent, AgentConfig, Domain, Evidence, EvidenceType, KeyPair
from otvp_agent.agents import CollectionContext, EvaluationResult
from otvp_agent.agents.supabase.base import SupabaseCollector, SupabaseEvaluator
from otvp_agent.agents.supabase.connection import SupabaseConnection
from otvp_agent.agents.supabase.constants import (
    DOMAIN_RLS_POLICY_QUALITY,
    SYSTEM_SCHEMAS,
)
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.supabase_rls_quality")


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


# ── Anti-Pattern Detection ─────────────────────────────────────────

def _normalize_expr(expression: str | None) -> str:
    """Normalize a policy expression for pattern matching."""
    if expression is None:
        return ""
    return expression.strip().lower()


def _is_using_true(expression: str | None) -> bool:
    """Check if a USING or WITH CHECK expression is effectively ``true``."""
    if expression is None:
        return False
    normalized = expression.strip().lower().replace("(", "").replace(")", "").strip()
    return normalized == "true"


def _missing_auth_uid_check(expression: str | None) -> bool:
    """Check if expression lacks an auth.uid() IS NOT NULL check.

    Policies that don't verify the user is authenticated can allow
    anonymous access even on the 'authenticated' role if tokens are
    misconfigured.
    """
    if expression is None:
        return True  # No expression = no auth check
    norm = _normalize_expr(expression)
    # Look for auth.uid() references — any form of auth.uid() presence
    # indicates the policy is at least checking who the user is
    return "auth.uid()" not in norm


def _references_raw_user_meta(expression: str | None) -> bool:
    """Check if expression references raw_user_meta_data.

    raw_user_meta_data is user-modifiable via the Supabase Auth API,
    so using it in security-critical policy decisions is dangerous.
    """
    if expression is None:
        return False
    norm = _normalize_expr(expression)
    return "raw_user_meta_data" in norm


def _is_overly_complex(expression: str | None, threshold: int = 500) -> bool:
    """Flag expressions that are unusually long, which may indicate
    logic errors or policies that are hard to audit.
    """
    if expression is None:
        return False
    return len(expression.strip()) > threshold


def _parse_roles(roles: str | list | None) -> list[str]:
    """Normalize the ``roles`` column from pg_policies into a list."""
    if roles is None:
        return []
    if isinstance(roles, list):
        return [str(r) for r in roles]
    cleaned = str(roles).strip("{}")
    return [r.strip() for r in cleaned.split(",") if r.strip()]


# All DML commands that RLS can cover
ALL_COMMANDS = {"SELECT", "INSERT", "UPDATE", "DELETE"}


def _analyze_policy(row: dict) -> dict:
    """Analyze a single policy row for anti-patterns.

    Returns a dict with the policy info plus a list of findings.
    """
    parsed_roles = _parse_roles(row.get("roles"))
    qual = row.get("qual")
    with_check = row.get("with_check")
    cmd = row.get("cmd", "ALL")

    findings: list[dict] = []

    # 1. USING(true) — effectively disables RLS for reads
    if _is_using_true(qual):
        severity = "critical" if "anon" in parsed_roles or not parsed_roles else "high"
        findings.append({
            "pattern": "using_true",
            "severity": severity,
            "detail": f"USING (true) on policy '{row['policyname']}' — bypasses row filtering",
        })

    # 2. WITH CHECK(true) — allows any row to be written
    if _is_using_true(with_check):
        severity = "high" if "anon" in parsed_roles or not parsed_roles else "medium"
        findings.append({
            "pattern": "with_check_true",
            "severity": severity,
            "detail": f"WITH CHECK (true) on policy '{row['policyname']}' — allows unrestricted writes",
        })

    # 3. Missing auth.uid() check on authenticated role
    if "authenticated" in parsed_roles:
        if _missing_auth_uid_check(qual) and not _is_using_true(qual):
            findings.append({
                "pattern": "missing_auth_uid",
                "severity": "medium",
                "detail": (
                    f"Policy '{row['policyname']}' for 'authenticated' role "
                    "does not reference auth.uid() — may not properly scope data to the user"
                ),
            })

    # 4. raw_user_meta_data in security decisions
    for expr, expr_name in [(qual, "USING"), (with_check, "WITH CHECK")]:
        if _references_raw_user_meta(expr):
            findings.append({
                "pattern": "raw_user_meta_data",
                "severity": "high",
                "detail": (
                    f"Policy '{row['policyname']}' references raw_user_meta_data in "
                    f"{expr_name} clause — this field is user-modifiable via the Auth API"
                ),
            })

    # 5. Overly complex expressions
    for expr, expr_name in [(qual, "USING"), (with_check, "WITH CHECK")]:
        if _is_overly_complex(expr):
            findings.append({
                "pattern": "overly_complex",
                "severity": "low",
                "detail": (
                    f"Policy '{row['policyname']}' has a {expr_name} clause over "
                    f"500 chars — may be hard to audit for correctness"
                ),
            })

    return {
        "name": row["policyname"],
        "permissive": row.get("permissive", "PERMISSIVE"),
        "roles": parsed_roles,
        "command": cmd,
        "qual": qual,
        "with_check": with_check,
        "findings": findings,
    }


# ── Collector ──────────────────────────────────────────────────────


class PolicyQualityCollector(SupabaseCollector):
    """Collects RLS policy details and analyzes them for anti-patterns."""

    domain = DOMAIN_RLS_POLICY_QUALITY

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        conn = self.connection
        if conn is None:
            raise RuntimeError("PolicyQualityCollector requires a SupabaseConnection.")

        # 1. Fetch tables with RLS status
        tables = conn.execute(SQL_TABLES)

        # 2. Fetch all policies
        policies_raw = conn.execute(SQL_POLICIES)

        # Index policies by schema.table and analyze each one
        policies_by_table: dict[str, list[dict]] = {}
        for row in policies_raw:
            key = f"{row['schemaname']}.{row['tablename']}"
            analyzed = _analyze_policy(row)
            policies_by_table.setdefault(key, []).append(analyzed)

        # Build one Evidence item per table (only tables with RLS enabled)
        evidence_items: list[Evidence] = []

        for tbl in tables:
            schema = tbl["schemaname"]
            table_name = tbl["tablename"]
            resource_id = f"{schema}.{table_name}"
            rls_enabled = bool(tbl.get("rowsecurity", False))

            # Skip tables without RLS — Agent 12 handles that
            if not rls_enabled:
                continue

            table_policies = policies_by_table.get(resource_id, [])

            # Determine command coverage
            covered_commands: set[str] = set()
            for pol in table_policies:
                cmd = pol["command"]
                if cmd == "ALL":
                    covered_commands = ALL_COMMANDS.copy()
                else:
                    covered_commands.add(cmd)
            missing_commands = sorted(ALL_COMMANDS - covered_commands)

            # Collect all findings across policies for this table
            all_findings: list[dict] = []
            for pol in table_policies:
                all_findings.extend(pol["findings"])

            # Determine severity counts
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in all_findings:
                sev = f.get("severity", "low")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            # Flag missing command coverage
            if missing_commands and table_policies:
                all_findings.append({
                    "pattern": "incomplete_command_coverage",
                    "severity": "medium",
                    "detail": (
                        f"Table {resource_id} has policies but missing coverage "
                        f"for: {', '.join(missing_commands)}"
                    ),
                })

            # Quality verdict for this table
            has_critical = severity_counts["critical"] > 0
            has_high = severity_counts["high"] > 0
            has_medium = severity_counts["medium"] > 0 or len(missing_commands) > 0

            if not table_policies:
                quality = "no_policies"
            elif has_critical or has_high:
                quality = "poor"
            elif has_medium:
                quality = "needs_improvement"
            else:
                quality = "good"

            evidence_items.append(
                self.make_evidence(
                    resource_id=resource_id,
                    observation={
                        "table_schema": schema,
                        "table_name": table_name,
                        "rls_enabled": True,
                        "policy_count": len(table_policies),
                        "policies": table_policies,
                        "covered_commands": sorted(covered_commands),
                        "missing_commands": missing_commands,
                        "findings": all_findings,
                        "severity_counts": severity_counts,
                        "quality": quality,
                    },
                    tags={
                        "framework": "soc2",
                        "criteria": "CC6.1,CC6.3",
                        "agent": "supabase-rls-policy-quality",
                    },
                )
            )

        return evidence_items


# ── Evaluator ──────────────────────────────────────────────────────


class PolicyQualityEvaluator(SupabaseEvaluator):
    """Evaluates the quality of RLS policies across all tables."""

    domain = DOMAIN_RLS_POLICY_QUALITY
    assertion = (
        "All RLS policies on exposed tables follow security best practices "
        "with no dangerous anti-patterns"
    )

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(
                result=ClaimResult.NOT_APPLICABLE,
                confidence=1.0,
                assessment=(
                    "No tables with RLS enabled found in exposed schemas. "
                    "Nothing to evaluate for policy quality."
                ),
                evidence_ids=[],
            )

        good_tables: list[str] = []
        needs_improvement_tables: list[dict] = []
        poor_tables: list[dict] = []
        all_recommendations: list[str] = []

        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            schema = obs.get("table_schema", "?")
            table = obs.get("table_name", "?")
            resource_id = f"{schema}.{table}"
            quality = obs.get("quality", "unknown")
            findings = obs.get("findings", [])
            missing_cmds = obs.get("missing_commands", [])

            if quality == "good":
                good_tables.append(resource_id)
            elif quality == "needs_improvement":
                needs_improvement_tables.append({
                    "table": resource_id,
                    "issues": [f["detail"] for f in findings],
                })
                for f in findings:
                    all_recommendations.append(
                        _recommendation_for(resource_id, f)
                    )
            else:
                # poor or no_policies
                poor_tables.append({
                    "table": resource_id,
                    "issues": [f["detail"] for f in findings],
                })
                for f in findings:
                    all_recommendations.append(
                        _recommendation_for(resource_id, f)
                    )

        total = len(evidence_items)
        good_count = len(good_tables)
        needs_improvement_count = len(needs_improvement_tables)
        poor_count = len(poor_tables)

        all_evidence_ids = [e.evidence_id for e in evidence_items]

        # Aggregate result
        if good_count == total:
            return EvaluationResult(
                result=ClaimResult.SATISFIED,
                confidence=1.0,
                assessment=(
                    f"All {total} table(s) with RLS have well-structured policies. "
                    "No anti-patterns detected. 100% of population verified."
                ),
                evidence_ids=all_evidence_ids,
            )

        if good_count == 0 and needs_improvement_count == 0:
            # All poor
            return EvaluationResult(
                result=ClaimResult.NOT_SATISFIED,
                confidence=1.0,
                assessment=(
                    f"All {total} table(s) have critical or high-severity policy issues. "
                    f"{_issue_summary(poor_tables)}"
                ),
                caveats=[
                    f"{t['table']}: {'; '.join(t['issues'][:3])}"
                    for t in poor_tables[:10]
                ],
                recommendations=_dedupe(all_recommendations)[:5],
                evidence_ids=all_evidence_ids,
            )

        # Mixed results — confidence = good / total
        confidence = round(good_count / total, 3)

        caveats = []
        for t in poor_tables[:5]:
            caveats.append(f"{t['table']}: {'; '.join(t['issues'][:2])}")
        for t in needs_improvement_tables[:5]:
            caveats.append(f"{t['table']}: {'; '.join(t['issues'][:2])}")

        return EvaluationResult(
            result=ClaimResult.PARTIAL,
            confidence=confidence,
            assessment=(
                f"{good_count}/{total} table(s) have good policy quality. "
                f"{poor_count} table(s) have critical/high issues, "
                f"{needs_improvement_count} need improvement."
            ),
            caveats=caveats,
            recommendations=_dedupe(all_recommendations)[:5],
            evidence_ids=all_evidence_ids,
        )


def _recommendation_for(table: str, finding: dict) -> str:
    """Generate a targeted recommendation for a specific finding."""
    pattern = finding.get("pattern", "")
    if pattern == "using_true":
        return (
            f"Replace USING (true) with a proper row filter on {table}. "
            "Example: USING (auth.uid() = user_id)"
        )
    if pattern == "with_check_true":
        return (
            f"Replace WITH CHECK (true) with validation on {table}. "
            "Example: WITH CHECK (auth.uid() = user_id)"
        )
    if pattern == "missing_auth_uid":
        return (
            f"Add auth.uid() check to authenticated-role policies on {table} "
            "to properly scope data to the requesting user."
        )
    if pattern == "raw_user_meta_data":
        return (
            f"Avoid using raw_user_meta_data in policies on {table} — "
            "it is user-modifiable. Use app_metadata or a lookup table instead."
        )
    if pattern == "incomplete_command_coverage":
        return (
            f"Add RLS policies for all DML commands on {table}. "
            f"Missing: {finding.get('detail', '').split('for: ')[-1]}"
        )
    if pattern == "overly_complex":
        return (
            f"Simplify or break apart the complex policy on {table} "
            "to make it easier to audit."
        )
    return f"Review policy issue on {table}: {finding.get('detail', '')}"


def _issue_summary(tables: list[dict]) -> str:
    """One-line summary of issues across tables."""
    patterns: dict[str, int] = {}
    for t in tables:
        for issue in t.get("issues", []):
            # Extract pattern name from the issue text
            for p in ["USING (true)", "WITH CHECK (true)", "auth.uid()",
                       "raw_user_meta_data", "missing coverage"]:
                if p.lower() in issue.lower():
                    patterns[p] = patterns.get(p, 0) + 1
                    break
    if not patterns:
        return ""
    parts = [f"{count} {name}" for name, count in sorted(patterns.items(), key=lambda x: -x[1])]
    return "Issues: " + ", ".join(parts) + "."


def _dedupe(items: list[str]) -> list[str]:
    """Remove duplicate recommendations while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


# ── Composite Agent ────────────────────────────────────────────────


class SupabaseRLSQualityAgent:
    """Orchestrates RLS policy quality verification for a Supabase project."""

    def __init__(self, agent: Agent, connection: SupabaseConnection) -> None:
        self.agent = agent
        self.connection = connection
        self.collector = PolicyQualityCollector()
        self.evaluator = PolicyQualityEvaluator()

    @classmethod
    def create(
        cls,
        project_ref: str | None = None,
        host: str | None = None,
        password: str | None = None,
    ) -> SupabaseRLSQualityAgent:
        keys = KeyPair.generate()
        config = AgentConfig(
            agent_id="supabase-rls-quality-agent-v1",
            vendor="OTVP Reference / Killswitch Advisory",
            version="1.0.0",
            key_pair=keys,
            domains=[Domain.RLS_POLICY_QUALITY],
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
        print("  OTVP Supabase Agent: RLS Policy Quality")
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

        print(f"  Collected {len(evidence)} table evidence items (tables with RLS enabled)")
        if evidence:
            good = sum(
                1 for e in evidence
                if isinstance(e.observation, dict) and e.observation.get("quality") == "good"
            )
            needs_work = sum(
                1 for e in evidence
                if isinstance(e.observation, dict) and e.observation.get("quality") == "needs_improvement"
            )
            poor = sum(
                1 for e in evidence
                if isinstance(e.observation, dict) and e.observation.get("quality") == "poor"
            )
            print(f"    Good policy quality:    {good}")
            print(f"    Needs improvement:      {needs_work}")
            print(f"    Poor (critical/high):   {poor}")
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
            domain=DOMAIN_RLS_POLICY_QUALITY,
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
        output_path = "supabase_rls_quality_envelope.json"
        with open(output_path, "w") as f:
            f.write(envelope.to_json(indent=2))
        print(f"\n  Envelope saved to: {output_path}")


# ── CLI ────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OTVP Supabase RLS Policy Quality Agent",
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
        print("  Set it to your Supabase pooler host, e.g.: aws-0-us-east-1.pooler.supabase.com", file=sys.stderr)
        sys.exit(1)
    if not password:
        print("ERROR: SUPABASE_DB_PASSWORD environment variable is required.", file=sys.stderr)
        sys.exit(1)

    agent = SupabaseRLSQualityAgent.create(
        project_ref=args.project_ref,
    )
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))


if __name__ == "__main__":
    main()
