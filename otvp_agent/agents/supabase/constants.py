"""Shared constants for all Supabase verification agents."""
from __future__ import annotations

# Schemas managed by Supabase internals — never in scope for customer verification.
# This list covers Supabase platform schemas across current versions.
# User-installed extensions (e.g. postgis) create schemas that should NOT be excluded.
SYSTEM_SCHEMAS = [
    "pg_catalog",
    "information_schema",
    "auth",
    "storage",
    "supabase_functions",
    "supabase_migrations",
    "extensions",
    "graphql",
    "graphql_public",
    "realtime",
    "pgsodium",
    "pgsodium_masks",
    "vault",
    "_analytics",
    "_realtime",
    "supabase_auth",
    "net",
    "pgbouncer",
    "cron",
]

# The three JWT roles that the Supabase Data API uses.
SUPABASE_API_ROLES = ["anon", "authenticated", "service_role"]

# Default schema exposed via PostgREST / Data API.
EXPOSED_SCHEMA_DEFAULT = "public"

# ── OTVP domain paths for Supabase agents ──────────────────────────

DOMAIN_RLS = "data_protection.access_control.row_level_security"
DOMAIN_RLS_POLICY_QUALITY = "data_protection.access_control.policy_quality"
DOMAIN_AUTH_CONFIG = "identity_and_access.authentication.configuration"
DOMAIN_MFA_ENROLLMENT = "identity_and_access.authentication.multi_factor"
DOMAIN_API_KEY_HYGIENE = "identity_and_access.credentials.api_keys"
DOMAIN_DATA_API_HARDENING = "network_security.api_surface.data_api"
DOMAIN_POSTGREST_EXPOSURE = "network_security.api_surface.postgrest"
DOMAIN_STORAGE_BUCKETS = "data_protection.storage.bucket_access"
DOMAIN_EDGE_FUNCTIONS = "application_security.serverless.edge_functions"
DOMAIN_NETWORK_RESTRICTIONS = "network_security.access_controls.network_restrictions"
DOMAIN_DB_ROLE_PRIVILEGES = "identity_and_access.authorization.database_roles"
DOMAIN_AUDIT_LOGGING = "detection_and_response.logging.audit_logging"
DOMAIN_REALTIME_CHANNELS = "data_protection.realtime.channel_access"

# ── SOC 2 criteria mappings ─────────────────────────────────────────

SOC2_MAPPINGS: dict[str, list[str]] = {
    DOMAIN_RLS: ["CC6.1", "CC6.3"],
    DOMAIN_RLS_POLICY_QUALITY: ["CC6.1", "CC6.3"],
    DOMAIN_AUTH_CONFIG: ["CC6.1", "CC6.2"],
    DOMAIN_MFA_ENROLLMENT: ["CC6.1", "CC6.2"],
    DOMAIN_API_KEY_HYGIENE: ["CC6.1", "CC6.6"],
    DOMAIN_DATA_API_HARDENING: ["CC6.1", "CC6.6", "CC6.7"],
    DOMAIN_POSTGREST_EXPOSURE: ["CC6.1", "CC6.6"],
    DOMAIN_STORAGE_BUCKETS: ["CC6.1", "CC6.7"],
    DOMAIN_EDGE_FUNCTIONS: ["CC6.1", "CC6.6"],
    DOMAIN_NETWORK_RESTRICTIONS: ["CC6.6", "CC6.7"],
    DOMAIN_DB_ROLE_PRIVILEGES: ["CC6.1", "CC6.3"],
    DOMAIN_AUDIT_LOGGING: ["CC7.1", "CC7.2", "CC7.3"],
    DOMAIN_REALTIME_CHANNELS: ["CC6.1", "CC6.7"],
}
