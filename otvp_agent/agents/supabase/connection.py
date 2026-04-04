"""Supabase database connection for verification agents."""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("otvp.agent.supabase.connection")

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    psycopg2 = None  # type: ignore[assignment]


class SupabaseConnectionError(Exception):
    """Raised when the agent cannot connect to the Supabase database."""


class SupabaseConnection:
    """Manages a Postgres connection to a Supabase project database.

    Reads connection parameters from environment variables by default,
    with optional constructor overrides.  Designed as a context manager::

        with SupabaseConnection() as conn:
            rows = conn.execute("SELECT 1")
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        dbname: str | None = None,
        user: str | None = None,
        password: str | None = None,
        project_ref: str | None = None,
        sslmode: str | None = None,
    ) -> None:
        self.host = host or os.environ.get("SUPABASE_DB_HOST", "")
        self.port = port or int(os.environ.get("SUPABASE_DB_PORT", "5432"))
        self.dbname = dbname or os.environ.get("SUPABASE_DB_NAME", "postgres")
        self.user = user or os.environ.get("SUPABASE_DB_USER", "postgres")
        self.password = password or os.environ.get("SUPABASE_DB_PASSWORD", "")
        self._project_ref = project_ref or os.environ.get("SUPABASE_PROJECT_REF", "")
        self.sslmode = sslmode or os.environ.get("SUPABASE_DB_SSLMODE", "require")
        self._conn: Any = None

    @property
    def project_ref(self) -> str:
        return self._project_ref

    def connect(self) -> None:
        if psycopg2 is None:
            raise SupabaseConnectionError(
                "psycopg2 is not installed. "
                "Install it with: pip install psycopg2-binary"
            )
        if not self.host:
            raise SupabaseConnectionError(
                "SUPABASE_DB_HOST is not set. "
                "Provide it via environment variable or constructor parameter."
            )
        try:
            self._conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                dbname=self.dbname,
                user=self.user,
                password=self.password,
                sslmode=self.sslmode,
                connect_timeout=10,
            )
            self._conn.set_session(readonly=True, autocommit=True)
            logger.info("Connected to %s:%s/%s", self.host, self.port, self.dbname)
        except Exception as exc:
            raise SupabaseConnectionError(
                f"Failed to connect to {self.host}:{self.port}/{self.dbname}: {exc}"
            ) from exc

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
            logger.info("Connection closed.")

    def execute(self, query: str, params: tuple[Any, ...] | None = None) -> list[dict[str, Any]]:
        """Execute a read-only SQL query and return rows as dicts."""
        if self._conn is None or self._conn.closed:
            raise SupabaseConnectionError("Not connected. Call connect() first.")
        with self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query, params)
            return [dict(row) for row in cur.fetchall()]

    # Context manager support
    def __enter__(self) -> SupabaseConnection:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
