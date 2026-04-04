"""Base classes for Supabase verification agents."""
from __future__ import annotations

from typing import Any

from otvp_agent.agents import Collector, Evaluator
from otvp_agent.agents.supabase.connection import SupabaseConnection
from otvp_agent.evidence.models import Evidence, EvidenceType


class SupabaseCollector(Collector):
    """Base collector for Supabase agents.

    Provides database connectivity and a helper to create CONFIGURATION
    evidence items with consistent source metadata.
    """

    source_type: str = "database_query"
    provider: str = "supabase"

    def __init__(self, connection: SupabaseConnection | None = None) -> None:
        self.connection: SupabaseConnection | None = connection

    def make_evidence(
        self,
        resource_id: str,
        observation: dict[str, Any],
        tags: dict[str, str] | None = None,
    ) -> Evidence:
        """Create a CONFIGURATION evidence item with Supabase source metadata."""
        project_ref = self.connection.project_ref if self.connection else ""
        return Evidence(
            evidence_type=EvidenceType.CONFIGURATION,
            domain=self.domain,
            source={
                "provider": "supabase",
                "service": "postgres",
                "resource_type": "table",
                "resource_id": resource_id,
                "project_ref": project_ref,
                "collection_method": "sql_query",
            },
            observation=observation,
            tags=tags or {},
        )


class SupabaseEvaluator(Evaluator):
    """Base evaluator for Supabase agents.

    Provides a consistent foundation for Supabase-specific evaluation logic.
    Shared helper methods can be added here as future agents need them.
    """

    provider: str = "supabase"
