#!/usr/bin/env python3
"""
OTVP Supabase Agent: Database Role Privileges

Verifies database role configurations: checks for roles with SUPERUSER,
BYPASSRLS, CREATEDB, or CREATEROLE privileges that shouldn't have them,
and validates that API roles have minimal privileges.

Maps to SOC 2 CC6.1, CC6.3.

Usage:
    export SUPABASE_DB_HOST=... SUPABASE_DB_PORT=6543 SUPABASE_DB_USER=...
    export SUPABASE_DB_PASSWORD=... SUPABASE_PROJECT_REF=...
    python run_supabase_db_roles_agent.py
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
from otvp_agent.agents.supabase.constants import DOMAIN_DB_ROLE_PRIVILEGES, SUPABASE_API_ROLES
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.supabase_db_roles")

# Supabase platform roles that legitimately need elevated privileges
PLATFORM_ROLES = [
    "postgres", "supabase_admin", "supabase_auth_admin",
    "supabase_storage_admin", "supabase_replication_admin",
    "supabase_realtime_admin", "supabase_functions_admin",
    "dashboard_user", "pgbouncer", "pgsodium_keyholder",
    "pgsodium_keymaker", "pgsodium_keyiduser",
    "supabase_etl_admin", "supabase_read_only_user",
]

SQL_ALL_ROLES = """
SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb,
       rolcanlogin, rolreplication, rolbypassrls, rolconnlimit
FROM pg_roles
WHERE rolname NOT LIKE 'pg_%'
ORDER BY rolname;
"""

SQL_ROLE_MEMBERSHIPS = """
SELECT r.rolname AS role_name,
       m.rolname AS member_of
FROM pg_auth_members am
JOIN pg_roles r ON am.member = r.oid
JOIN pg_roles m ON am.roleid = m.oid
WHERE r.rolname NOT LIKE 'pg_%'
ORDER BY r.rolname, m.rolname;
"""


class DBRoleCollector(SupabaseCollector):
    domain = DOMAIN_DB_ROLE_PRIVILEGES

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        conn = self.connection
        if conn is None:
            raise RuntimeError("DBRoleCollector requires a SupabaseConnection.")

        evidence_items: list[Evidence] = []

        # 1. All roles and their privileges
        roles = conn.execute(SQL_ALL_ROLES)

        # Check for dangerous privileges on non-platform roles
        dangerous_roles = []
        for role in roles:
            name = role["rolname"]
            if name in PLATFORM_ROLES or name in SUPABASE_API_ROLES:
                continue

            flags = []
            if role.get("rolsuper"):
                flags.append("SUPERUSER")
            if role.get("rolbypassrls"):
                flags.append("BYPASSRLS")
            if role.get("rolcreatedb"):
                flags.append("CREATEDB")
            if role.get("rolcreaterole"):
                flags.append("CREATEROLE")
            if role.get("rolreplication"):
                flags.append("REPLICATION")

            if flags:
                dangerous_roles.append({"role": name, "privileges": flags})

        passed = len(dangerous_roles) == 0
        evidence_items.append(self.make_evidence(
            resource_id="roles.elevated_privileges",
            observation={
                "check": "elevated_privileges",
                "total_roles": len(roles),
                "dangerous_roles": dangerous_roles,
                "dangerous_count": len(dangerous_roles),
                "passed": passed,
                "severity": "high" if not passed else "none",
                "detail": (
                    f"{len(dangerous_roles)} non-platform role(s) have elevated privileges: "
                    f"{', '.join(r['role'] + '(' + ','.join(r['privileges']) + ')' for r in dangerous_roles[:5])}"
                    if not passed else
                    "No non-platform roles have elevated privileges."
                ),
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.3", "agent": "supabase-db-role-privileges"},
        ))

        # 2. API roles privilege check
        for api_role in SUPABASE_API_ROLES:
            role_data = next((r for r in roles if r["rolname"] == api_role), None)
            if role_data is None:
                evidence_items.append(self.make_evidence(
                    resource_id=f"roles.api.{api_role}",
                    observation={
                        "check": f"api_role_{api_role}",
                        "role": api_role,
                        "exists": False,
                        "passed": True,
                        "severity": "none",
                        "detail": f"API role '{api_role}' does not exist (may be expected).",
                    },
                    tags={"framework": "soc2", "criteria": "CC6.1,CC6.3", "agent": "supabase-db-role-privileges"},
                ))
                continue

            issues = []
            if role_data.get("rolsuper"):
                issues.append("SUPERUSER")
            if role_data.get("rolbypassrls"):
                issues.append("BYPASSRLS")
            if role_data.get("rolcreatedb"):
                issues.append("CREATEDB")
            if role_data.get("rolcreaterole"):
                issues.append("CREATEROLE")

            # service_role legitimately has BYPASSRLS in Supabase
            if api_role == "service_role" and issues == ["BYPASSRLS"]:
                issues = []

            passed = len(issues) == 0
            severity = "critical" if issues else "none"

            evidence_items.append(self.make_evidence(
                resource_id=f"roles.api.{api_role}",
                observation={
                    "check": f"api_role_{api_role}",
                    "role": api_role,
                    "exists": True,
                    "can_login": role_data.get("rolcanlogin", False),
                    "superuser": role_data.get("rolsuper", False),
                    "bypass_rls": role_data.get("rolbypassrls", False),
                    "create_db": role_data.get("rolcreatedb", False),
                    "create_role": role_data.get("rolcreaterole", False),
                    "issues": issues,
                    "passed": passed,
                    "severity": severity,
                    "detail": (
                        f"API role '{api_role}' has unexpected privileges: {', '.join(issues)}"
                        if not passed else
                        f"API role '{api_role}' has appropriate privilege levels."
                    ),
                },
                tags={"framework": "soc2", "criteria": "CC6.1,CC6.3", "agent": "supabase-db-role-privileges"},
            ))

        # 3. Role memberships
        memberships = conn.execute(SQL_ROLE_MEMBERSHIPS)
        api_memberships = [m for m in memberships if m["role_name"] in SUPABASE_API_ROLES]

        evidence_items.append(self.make_evidence(
            resource_id="roles.memberships",
            observation={
                "check": "role_memberships",
                "total_memberships": len(memberships),
                "api_role_memberships": [
                    {"role": m["role_name"], "member_of": m["member_of"]}
                    for m in api_memberships
                ],
                "passed": True,
                "severity": "none",
                "detail": f"{len(memberships)} role membership(s) found, {len(api_memberships)} involving API roles.",
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.3", "agent": "supabase-db-role-privileges"},
        ))

        return evidence_items


class DBRoleEvaluator(SupabaseEvaluator):
    domain = DOMAIN_DB_ROLE_PRIVILEGES
    assertion = "Database roles follow least-privilege principles with no unnecessary elevated privileges on API-facing roles"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.INDETERMINATE, confidence=0.0,
                                    assessment="No database role evidence collected.", evidence_ids=[])

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
                                    assessment=f"All {total} database role checks pass.", evidence_ids=all_ids)
        if not passed:
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=1.0,
                                    assessment=f"All {total} role checks have issues.",
                                    caveats=[f"{f['check']}: {f['detail']}" for f in failed],
                                    recommendations=[_role_rec(f) for f in failed[:5]], evidence_ids=all_ids)

        confidence = round(len(passed) / total, 3)
        return EvaluationResult(result=ClaimResult.PARTIAL, confidence=confidence,
                                assessment=f"{len(passed)}/{total} role checks pass.",
                                caveats=[f"{f['check']} [{f['severity']}]: {f['detail']}" for f in failed],
                                recommendations=[_role_rec(f) for f in failed[:5]], evidence_ids=all_ids)


def _role_rec(f: dict) -> str:
    check = f["check"]
    if check == "elevated_privileges":
        return "Remove elevated privileges from non-platform roles: ALTER ROLE <name> NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;"
    if check.startswith("api_role_"):
        return f"Review and restrict privileges on API role. {f['detail']}"
    return f"Review: {f['detail']}"


class SupabaseDBRoleAgent:
    def __init__(self, agent: Agent, connection: SupabaseConnection) -> None:
        self.agent = agent
        self.connection = connection
        self.collector = DBRoleCollector()
        self.evaluator = DBRoleEvaluator()

    @classmethod
    def create(cls, project_ref: str | None = None) -> SupabaseDBRoleAgent:
        keys = KeyPair.generate()
        config = AgentConfig(agent_id="supabase-db-roles-agent-v1", vendor="OTVP Reference / Killswitch Advisory",
                             version="1.0.0", key_pair=keys, domains=[Domain.DB_ROLE_PRIVILEGES])
        return cls(agent=Agent(config), connection=SupabaseConnection(project_ref=project_ref))

    async def run(self, subject: str = "killswitch-advisory", relying_party: str | None = None) -> None:
        project_ref = self.connection.project_ref or "(unknown)"
        print("=" * 70)
        print("  OTVP Supabase Agent: Database Role Privileges")
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

        claim = self.agent.create_claim(domain=DOMAIN_DB_ROLE_PRIVILEGES, assertion=self.evaluator.assertion,
                                         result=result.result, confidence=result.confidence, evidence_refs=signed_refs,
                                         opinion=result.assessment, caveats=result.caveats, recommendations=result.recommendations,
                                         scope=ClaimScope(environment="production", services=["Supabase PostgreSQL"], regions=[project_ref]))
        envelope = self.agent.build_envelope(claims=[claim], subject=subject, relying_party=relying_party)

        print("-" * 70)
        print(envelope.summary())
        print()
        print(envelope.to_json(indent=2))

        output_path = "supabase_db_role_privileges_envelope.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  Envelope saved to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OTVP Supabase Database Role Privileges Agent")
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    parser.add_argument("--project-ref", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if not os.environ.get("SUPABASE_DB_HOST"):
        print("ERROR: SUPABASE_DB_HOST is required.", file=sys.stderr); sys.exit(1)
    if not os.environ.get("SUPABASE_DB_PASSWORD"):
        print("ERROR: SUPABASE_DB_PASSWORD is required.", file=sys.stderr); sys.exit(1)
    agent = SupabaseDBRoleAgent.create(project_ref=args.project_ref)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
