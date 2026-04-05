#!/usr/bin/env python3
"""
OTVP Supabase Agent: Audit Logging

Verifies audit logging configuration: pgAudit extension presence,
log configuration settings, and statement logging coverage.

Maps to SOC 2 CC7.1, CC7.2, CC7.3.

Usage:
    export SUPABASE_DB_HOST=... SUPABASE_DB_PORT=6543 SUPABASE_DB_USER=...
    export SUPABASE_DB_PASSWORD=... SUPABASE_PROJECT_REF=...
    python run_supabase_audit_log_agent.py
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
from otvp_agent.agents.supabase.constants import DOMAIN_AUDIT_LOGGING
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.supabase_audit_log")

SQL_PGAUDIT_EXTENSION = """
SELECT extname, extversion, n.nspname AS schema_name
FROM pg_extension e
JOIN pg_namespace n ON e.extnamespace = n.oid
WHERE extname = 'pgaudit';
"""

SQL_AVAILABLE_EXTENSIONS = """
SELECT name, default_version, installed_version, comment
FROM pg_available_extensions
WHERE name = 'pgaudit';
"""

SQL_LOG_SETTINGS = """
SELECT name, setting, unit, source, context
FROM pg_settings
WHERE name IN (
    'log_statement',
    'log_min_duration_statement',
    'log_connections',
    'log_disconnections',
    'log_duration',
    'log_line_prefix',
    'log_checkpoints',
    'pgaudit.log',
    'pgaudit.log_catalog',
    'pgaudit.log_level',
    'pgaudit.log_parameter',
    'pgaudit.log_relation',
    'pgaudit.log_statement_once',
    'pgaudit.role'
)
ORDER BY name;
"""


class AuditLogCollector(SupabaseCollector):
    domain = DOMAIN_AUDIT_LOGGING

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        conn = self.connection
        if conn is None:
            raise RuntimeError("AuditLogCollector requires a SupabaseConnection.")

        evidence_items: list[Evidence] = []

        # 1. pgAudit extension installed?
        pgaudit_rows = conn.execute(SQL_PGAUDIT_EXTENSION)
        pgaudit_installed = len(pgaudit_rows) > 0
        pgaudit_version = pgaudit_rows[0]["extversion"] if pgaudit_installed else None

        # Check if pgAudit is available but not installed
        available = conn.execute(SQL_AVAILABLE_EXTENSIONS)
        pgaudit_available = len(available) > 0

        if pgaudit_installed:
            detail = f"pgAudit extension v{pgaudit_version} is installed and active."
            severity = "none"
        elif pgaudit_available:
            detail = "pgAudit is available but NOT installed. Enable with: CREATE EXTENSION pgaudit;"
            severity = "high"
        else:
            detail = "pgAudit extension is not available on this instance."
            severity = "medium"

        evidence_items.append(self.make_evidence(
            resource_id="audit.pgaudit_extension",
            observation={
                "check": "pgaudit_extension",
                "installed": pgaudit_installed,
                "available": pgaudit_available,
                "version": pgaudit_version,
                "passed": pgaudit_installed,
                "severity": severity,
                "detail": detail,
            },
            tags={"framework": "soc2", "criteria": "CC7.1,CC7.2,CC7.3", "agent": "supabase-audit-logging"},
        ))

        # 2. Log configuration settings
        settings = conn.execute(SQL_LOG_SETTINGS)
        settings_dict = {s["name"]: s["setting"] for s in settings}

        # Check key settings
        log_statement = settings_dict.get("log_statement", "none")
        log_connections = settings_dict.get("log_connections", "off")
        log_disconnections = settings_dict.get("log_disconnections", "off")
        pgaudit_log = settings_dict.get("pgaudit.log", "none")

        evidence_items.append(self.make_evidence(
            resource_id="audit.log_settings",
            observation={
                "check": "log_settings",
                "settings": settings_dict,
                "log_statement": log_statement,
                "log_connections": log_connections,
                "log_disconnections": log_disconnections,
                "pgaudit_log": pgaudit_log,
                "passed": True,  # Informational
                "severity": "none",
                "detail": (
                    f"log_statement={log_statement}, log_connections={log_connections}, "
                    f"log_disconnections={log_disconnections}, pgaudit.log={pgaudit_log}."
                ),
            },
            tags={"framework": "soc2", "criteria": "CC7.1,CC7.2,CC7.3", "agent": "supabase-audit-logging"},
        ))

        # 3. Statement logging coverage
        # 'all' or 'mod' are good; 'ddl' is partial; 'none' is bad
        statement_levels = {"all": 3, "mod": 2, "ddl": 1, "none": 0}
        statement_level = statement_levels.get(log_statement, 0)

        # pgaudit.log can be 'all', 'read,write,ddl', etc.
        pgaudit_has_coverage = pgaudit_log and pgaudit_log.lower() not in ("none", "")

        has_adequate_logging = statement_level >= 2 or pgaudit_has_coverage
        passed = has_adequate_logging

        evidence_items.append(self.make_evidence(
            resource_id="audit.statement_coverage",
            observation={
                "check": "statement_logging_coverage",
                "log_statement_level": log_statement,
                "pgaudit_log_setting": pgaudit_log,
                "has_pgaudit_coverage": pgaudit_has_coverage,
                "has_statement_logging": statement_level >= 2,
                "passed": passed,
                "severity": "high" if not passed else "none",
                "detail": (
                    f"Adequate logging: log_statement={log_statement}, pgaudit.log={pgaudit_log}."
                    if passed else
                    f"Insufficient logging coverage: log_statement={log_statement}, pgaudit.log={pgaudit_log}. "
                    "Enable pgAudit or set log_statement to 'mod' or 'all'."
                ),
            },
            tags={"framework": "soc2", "criteria": "CC7.1,CC7.2,CC7.3", "agent": "supabase-audit-logging"},
        ))

        # 4. Connection logging
        conn_logging = log_connections == "on" and log_disconnections == "on"
        evidence_items.append(self.make_evidence(
            resource_id="audit.connection_logging",
            observation={
                "check": "connection_logging",
                "log_connections": log_connections,
                "log_disconnections": log_disconnections,
                "passed": conn_logging,
                "severity": "medium" if not conn_logging else "none",
                "detail": (
                    "Connection and disconnection logging is enabled."
                    if conn_logging else
                    f"Connection logging incomplete: log_connections={log_connections}, "
                    f"log_disconnections={log_disconnections}."
                ),
            },
            tags={"framework": "soc2", "criteria": "CC7.1,CC7.2", "agent": "supabase-audit-logging"},
        ))

        return evidence_items


class AuditLogEvaluator(SupabaseEvaluator):
    domain = DOMAIN_AUDIT_LOGGING
    assertion = "Database audit logging is configured with adequate statement coverage and connection tracking"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.INDETERMINATE, confidence=0.0,
                                    assessment="No audit logging evidence collected.", evidence_ids=[])

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
                                    assessment=f"All {total} audit logging checks pass.", evidence_ids=all_ids)
        if not passed:
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=1.0,
                                    assessment=f"All {total} audit logging checks have issues.",
                                    caveats=[f"{f['check']}: {f['detail']}" for f in failed],
                                    recommendations=[_audit_rec(f) for f in failed[:5]], evidence_ids=all_ids)

        confidence = round(len(passed) / total, 3)
        return EvaluationResult(result=ClaimResult.PARTIAL, confidence=confidence,
                                assessment=f"{len(passed)}/{total} audit logging checks pass.",
                                caveats=[f"{f['check']} [{f['severity']}]: {f['detail']}" for f in failed],
                                recommendations=[_audit_rec(f) for f in failed[:5]], evidence_ids=all_ids)


def _audit_rec(f: dict) -> str:
    check = f["check"]
    if check == "pgaudit_extension":
        return "Install pgAudit for comprehensive audit logging: CREATE EXTENSION pgaudit; then configure pgaudit.log = 'all' or 'write,ddl'."
    if check == "statement_logging_coverage":
        return "Enable statement logging: ALTER SYSTEM SET log_statement = 'mod'; or configure pgaudit.log for fine-grained control."
    if check == "connection_logging":
        return "Enable connection logging: ALTER SYSTEM SET log_connections = 'on'; ALTER SYSTEM SET log_disconnections = 'on';"
    return f"Review: {f['detail']}"


class SupabaseAuditLogAgent:
    def __init__(self, agent: Agent, connection: SupabaseConnection) -> None:
        self.agent = agent
        self.connection = connection
        self.collector = AuditLogCollector()
        self.evaluator = AuditLogEvaluator()

    @classmethod
    def create(cls, project_ref: str | None = None) -> SupabaseAuditLogAgent:
        keys = KeyPair.generate()
        config = AgentConfig(agent_id="supabase-audit-log-agent-v1", vendor="OTVP Reference / Killswitch Advisory",
                             version="1.0.0", key_pair=keys, domains=[Domain.AUDIT_LOGGING])
        return cls(agent=Agent(config), connection=SupabaseConnection(project_ref=project_ref))

    async def run(self, subject: str = "killswitch-advisory", relying_party: str | None = None) -> None:
        project_ref = self.connection.project_ref or "(unknown)"
        print("=" * 70)
        print("  OTVP Supabase Agent: Audit Logging")
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

        claim = self.agent.create_claim(domain=DOMAIN_AUDIT_LOGGING, assertion=self.evaluator.assertion,
                                         result=result.result, confidence=result.confidence, evidence_refs=signed_refs,
                                         opinion=result.assessment, caveats=result.caveats, recommendations=result.recommendations,
                                         scope=ClaimScope(environment="production", services=["Supabase PostgreSQL"], regions=[project_ref]))
        envelope = self.agent.build_envelope(claims=[claim], subject=subject, relying_party=relying_party)

        print("-" * 70)
        print(envelope.summary())
        print()
        print(envelope.to_json(indent=2))

        output_path = "supabase_audit_logging_envelope.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  Envelope saved to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OTVP Supabase Audit Logging Agent")
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    parser.add_argument("--project-ref", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if not os.environ.get("SUPABASE_DB_HOST"):
        print("ERROR: SUPABASE_DB_HOST is required.", file=sys.stderr); sys.exit(1)
    if not os.environ.get("SUPABASE_DB_PASSWORD"):
        print("ERROR: SUPABASE_DB_PASSWORD is required.", file=sys.stderr); sys.exit(1)
    agent = SupabaseAuditLogAgent.create(project_ref=args.project_ref)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
