# OTVP Agent SDK

Reference implementation of the [Open Transparency Verification Platform](https://github.com/wharmer68/otvp). Autonomous Python agents that audit AWS infrastructure and Supabase project configurations against SOC 2 Trust Services Common Criteria, producing cryptographically signed trust envelopes.

**24 agents** across two platforms: 11 AWS infrastructure agents + 13 Supabase security agents.

## Architecture

```
Collect → Sign (Ed25519) → Store (Merkle) → Evaluate → Claim → Envelope → Verify
```

Every agent follows the same pipeline. Evidence is signed individually, stored in an append-only Merkle tree, evaluated against control criteria, and wrapped in a verifiable trust envelope.

**Agents are read-only.** They observe and report. They never modify infrastructure.

## Quick Start

```bash
# 1. Create virtual environment
python3 -m venv otvp-env
source otvp-env/bin/activate

# 2. Install dependencies
pip install -r requirements.txt
```

### AWS Agents

```bash
# Configure AWS credentials (read-only IAM role recommended)
export AWS_PROFILE=your-profile
export AWS_DEFAULT_REGION=us-east-2

# Run any AWS agent
python run_agent.py              # Encryption at Rest
python run_mfa_agent.py          # IAM MFA Enforcement
python run_network_agent.py      # Network Segmentation
```

### Supabase Agents — SQL

Agents that query the database directly (12, 13, 17, 18, 19, 22, 23, 24):

```bash
# Configure database connection (via Supabase pooler)
export SUPABASE_DB_HOST=aws-0-<region>.pooler.supabase.com
export SUPABASE_DB_PORT=6543
export SUPABASE_DB_USER=postgres.<project-ref>
export SUPABASE_DB_PASSWORD=<db-password>
export SUPABASE_PROJECT_REF=<project-ref>

# Run any SQL-based agent
python run_supabase_rls_agent.py
python run_supabase_db_roles_agent.py
python run_supabase_audit_log_agent.py
```

### Supabase Agents — Management API

Agents that use the Supabase Management API (14, 16, 20, 21):

```bash
# Get a personal access token from:
# https://supabase.com/dashboard/account/tokens
export SUPABASE_ACCESS_TOKEN=sbp_xxxxxxxxxxxxx
export SUPABASE_PROJECT_REF=<project-ref>

# Run any Management API agent
python run_supabase_auth_config_agent.py
python run_supabase_api_key_agent.py
python run_supabase_edge_functions_agent.py
python run_supabase_network_agent.py
```

### Supabase Agents — Hybrid

Agent 15 (MFA Enrollment) needs both database and Management API credentials:

```bash
# Set both SQL and Management API env vars above, then:
python run_supabase_mfa_agent.py
```

## Agent Reference

### AWS Agents (1-11)

| # | Control | Runner | SOC 2 |
|---|---------|--------|-------|
| 1 | Encryption at Rest | `run_agent.py` | CC6.1, CC6.7 |
| 2 | IAM MFA Enforcement | `run_mfa_agent.py` | CC6.1 |
| 3 | KMS Key Management | `run_kms_agent.py` | CC6.1, CC6.7 |
| 4 | Network Segmentation | `run_network_agent.py` | CC6.1, CC6.6 |
| 5 | Audit Logging | `run_logging_agent.py` | CC7.1, CC7.2 |
| 6 | Account Lifecycle | `run_lifecycle_agent.py` | CC6.2, CC6.5 |
| 7 | Encryption in Transit | `run_transit_agent.py` | CC6.1, CC6.7 |
| 8 | Ingress Controls | `run_ingress_agent.py` | CC6.6 |
| 9 | Least Privilege | `run_privilege_agent.py` | CC6.3 |
| 10 | Vulnerability Management | `run_vuln_agent.py` | CC7.1 |
| 11 | Backup & Recovery | `run_backup_agent.py` | CC7.5, CC9.1 |

### Supabase Agents (12-24)

| # | Control | Runner | Source | SOC 2 |
|---|---------|--------|--------|-------|
| 12 | RLS Enforcement | `run_supabase_rls_agent.py` | SQL | CC6.1, CC6.3 |
| 13 | RLS Policy Quality | `run_supabase_rls_quality_agent.py` | SQL | CC6.1, CC6.3 |
| 14 | Auth Configuration | `run_supabase_auth_config_agent.py` | Mgmt API | CC6.1, CC6.2 |
| 15 | MFA Enrollment | `run_supabase_mfa_agent.py` | Hybrid | CC6.1, CC6.2 |
| 16 | API Key Hygiene | `run_supabase_api_key_agent.py` | Mgmt API | CC6.1, CC6.6 |
| 17 | Data API Hardening | `run_supabase_data_api_agent.py` | SQL | CC6.1, CC6.6, CC6.7 |
| 18 | PostgREST Exposure | `run_supabase_postgrest_agent.py` | SQL | CC6.1, CC6.6 |
| 19 | Storage Bucket Policy | `run_supabase_storage_agent.py` | SQL | CC6.1, CC6.7 |
| 20 | Edge Function Security | `run_supabase_edge_functions_agent.py` | Mgmt API | CC6.1, CC6.6 |
| 21 | Network Restrictions | `run_supabase_network_agent.py` | Mgmt API | CC6.6, CC6.7 |
| 22 | DB Role Privileges | `run_supabase_db_roles_agent.py` | SQL | CC6.1, CC6.3 |
| 23 | Audit Logging | `run_supabase_audit_log_agent.py` | SQL | CC7.1, CC7.2, CC7.3 |
| 24 | Realtime Channel Security | `run_supabase_realtime_agent.py` | SQL | CC6.1, CC6.7 |

## Trust Envelopes

Each agent run produces a JSON trust envelope — a point-in-time posture snapshot containing:

- Control identifier and SOC 2 mapping
- Claim result: `SATISFIED`, `PARTIAL`, `NOT_SATISFIED`, `NOT_APPLICABLE`, or `INDETERMINATE`
- Confidence score (0.0-1.0) based on direct resource-level assessment
- Ed25519 signatures on evidence, claims, and the envelope itself
- Merkle tree root for evidence integrity verification
- Scope, timestamps, and TTL

Output files are written to the repo root (e.g., `supabase_rls_enforcement_envelope.json`).

## Repository Structure

```
otvp-agent-sdk/
├── otvp_agent/                           # Core agent package
│   ├── core.py                           # Base agent class and execution logic
│   ├── envelope.py                       # Trust envelope schema and serialization
│   ├── claims.py                         # Claim definitions and results
│   ├── domains.py                        # Domain definitions and SOC 2 mappings
│   ├── agents/                           # Agent implementations
│   │   └── supabase/                     # Supabase shared infrastructure
│   │       ├── connection.py             # PostgreSQL connection (psycopg2)
│   │       ├── management.py             # Management API client (stdlib urllib)
│   │       ├── base.py                   # SupabaseCollector/Evaluator base classes
│   │       └── constants.py              # Domains, SOC 2 mappings, system schemas
│   ├── crypto/                           # Ed25519 signing and verification
│   ├── evidence/                         # Evidence collection and Merkle tree
│   └── query/                            # AWS query helpers
├── run_agent.py                          # AWS: Encryption at Rest
├── run_mfa_agent.py                      # AWS: IAM MFA Enforcement
├── run_kms_agent.py                      # AWS: KMS Key Management
├── run_network_agent.py                  # AWS: Network Segmentation
├── run_logging_agent.py                  # AWS: Audit Logging
├── run_lifecycle_agent.py                # AWS: Account Lifecycle
├── run_transit_agent.py                  # AWS: Encryption in Transit
├── run_ingress_agent.py                  # AWS: Ingress Controls
├── run_privilege_agent.py                # AWS: Least Privilege
├── run_vuln_agent.py                     # AWS: Vulnerability Management
├── run_backup_agent.py                   # AWS: Backup & Recovery
├── run_supabase_rls_agent.py             # Supabase: RLS Enforcement
├── run_supabase_rls_quality_agent.py     # Supabase: RLS Policy Quality
├── run_supabase_auth_config_agent.py     # Supabase: Auth Configuration
├── run_supabase_mfa_agent.py             # Supabase: MFA Enrollment
├── run_supabase_api_key_agent.py         # Supabase: API Key Hygiene
├── run_supabase_data_api_agent.py        # Supabase: Data API Hardening
├── run_supabase_postgrest_agent.py       # Supabase: PostgREST Exposure
├── run_supabase_storage_agent.py         # Supabase: Storage Bucket Policy
├── run_supabase_edge_functions_agent.py  # Supabase: Edge Function Security
├── run_supabase_network_agent.py         # Supabase: Network Restrictions
├── run_supabase_db_roles_agent.py        # Supabase: DB Role Privileges
├── run_supabase_audit_log_agent.py       # Supabase: Audit Logging
├── run_supabase_realtime_agent.py        # Supabase: Realtime Channel Security
└── requirements.txt
```

## Dependencies

```
cryptography>=41.0.0       # Ed25519 signing, all agents
boto3>=1.28.0              # AWS API access, AWS agents only
psycopg2-binary>=2.9.0    # PostgreSQL connectivity, Supabase SQL agents only
```

Supabase Management API agents use Python's stdlib `urllib` only — no additional dependencies.

## Development Rules

- **Read-only access** — agents never use write permissions (AWS or Supabase)
- **No credentials in code** — auth via environment variables, profiles, or IAM roles
- **Deterministic output** — same state produces the same envelope
- **Fail safe** — if a resource can't be assessed, report `INDETERMINATE`, not `SATISFIED`
- **Do not commit:** `otvp-env/`, `.env`, `*.log`, `__pycache__/`
