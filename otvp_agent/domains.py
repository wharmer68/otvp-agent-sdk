"""OTVP Control Domains — hierarchical taxonomy of security controls."""
from __future__ import annotations
from enum import Enum


class Domain(str, Enum):
    AUTHENTICATION_MFA = "identity_and_access.authentication.mfa_enforcement"
    AUTHORIZATION_LEAST_PRIVILEGE = "identity_and_access.authorization.least_privilege"
    ENCRYPTION_AT_REST = "data_protection.encryption.at_rest"
    ENCRYPTION_IN_TRANSIT = "data_protection.encryption.in_transit"
    ENCRYPTION_KEY_MGMT = "data_protection.encryption.key_management"
    NETWORK_SEGMENTATION = "network_security.segmentation"
    LOGGING_COMPLETENESS = "detection_and_response.logging.completeness"
    INCIDENT_RESPONSE = "detection_and_response.incident_response.plan_existence"
    BACKUP_TESTING = "operational_resilience.backup.testing"
    DISASTER_RECOVERY = "operational_resilience.disaster_recovery.plan_existence"
    ROW_LEVEL_SECURITY = "data_protection.access_control.row_level_security"
    RLS_POLICY_QUALITY = "data_protection.access_control.policy_quality"
    AUTH_CONFIGURATION = "identity_and_access.authentication.configuration"
    MFA_ENROLLMENT = "identity_and_access.authentication.multi_factor"
    API_KEY_HYGIENE = "identity_and_access.credentials.api_keys"
    DATA_API_HARDENING = "network_security.api_surface.data_api"
    POSTGREST_EXPOSURE = "network_security.api_surface.postgrest"
    STORAGE_BUCKETS = "data_protection.storage.bucket_access"
    EDGE_FUNCTIONS = "application_security.serverless.edge_functions"
    NETWORK_RESTRICTIONS = "network_security.access_controls.network_restrictions"
    DB_ROLE_PRIVILEGES = "identity_and_access.authorization.database_roles"
    AUDIT_LOGGING = "detection_and_response.logging.audit_logging"
    REALTIME_CHANNELS = "data_protection.realtime.channel_access"

    @property
    def category(self) -> str:
        return self.value.split(".")[0]

    @property
    def parent(self) -> str:
        parts = self.value.rsplit(".", 1)
        return parts[0] if len(parts) > 1 else self.value


FRAMEWORK_MAPPINGS: dict[str, dict[str, list[str]]] = {
    "data_protection.encryption.at_rest": {
        "SOC2_CC": ["CC6.1", "CC6.7"], "ISO27001": ["A.10.1.1", "A.10.1.2"],
        "NIST_CSF": ["PR.DS-1"], "PCI_DSS": ["3.4", "3.5"], "HIPAA": ["§164.312(a)(2)(iv)"],
    },
    "data_protection.encryption.in_transit": {
        "SOC2_CC": ["CC6.1", "CC6.7"], "ISO27001": ["A.13.1.1"],
        "NIST_CSF": ["PR.DS-2"], "PCI_DSS": ["4.1"], "HIPAA": ["§164.312(e)(1)"],
    },
    "data_protection.access_control.row_level_security": {
        "SOC2_CC": ["CC6.1", "CC6.3"], "ISO27001": ["A.9.4.1"],
        "NIST_CSF": ["PR.AC-4"], "HIPAA": ["§164.312(a)(1)"],
    },
    "data_protection.access_control.policy_quality": {
        "SOC2_CC": ["CC6.1", "CC6.3"], "ISO27001": ["A.9.4.1"],
        "NIST_CSF": ["PR.AC-4"], "HIPAA": ["§164.312(a)(1)"],
    },
    "identity_and_access.authentication.configuration": {
        "SOC2_CC": ["CC6.1", "CC6.2"], "ISO27001": ["A.9.4.2"],
        "NIST_CSF": ["PR.AC-7"], "HIPAA": ["§164.312(d)"],
    },
    "identity_and_access.authentication.multi_factor": {
        "SOC2_CC": ["CC6.1", "CC6.2"], "ISO27001": ["A.9.4.2"],
        "NIST_CSF": ["PR.AC-7"], "HIPAA": ["§164.312(d)"],
    },
    "identity_and_access.credentials.api_keys": {
        "SOC2_CC": ["CC6.1", "CC6.6"], "ISO27001": ["A.9.2.4"],
        "NIST_CSF": ["PR.AC-1"], "HIPAA": ["§164.312(d)"],
    },
    "network_security.api_surface.data_api": {
        "SOC2_CC": ["CC6.1", "CC6.6", "CC6.7"], "ISO27001": ["A.13.1.1"],
        "NIST_CSF": ["PR.AC-5"], "HIPAA": ["§164.312(e)(1)"],
    },
    "network_security.api_surface.postgrest": {
        "SOC2_CC": ["CC6.1", "CC6.6"], "ISO27001": ["A.13.1.1"],
        "NIST_CSF": ["PR.AC-5"],
    },
    "data_protection.storage.bucket_access": {
        "SOC2_CC": ["CC6.1", "CC6.7"], "ISO27001": ["A.8.2.3"],
        "NIST_CSF": ["PR.DS-1"], "HIPAA": ["§164.312(a)(1)"],
    },
    "application_security.serverless.edge_functions": {
        "SOC2_CC": ["CC6.1", "CC6.6"], "ISO27001": ["A.14.2.1"],
        "NIST_CSF": ["PR.AC-4"],
    },
    "network_security.access_controls.network_restrictions": {
        "SOC2_CC": ["CC6.6", "CC6.7"], "ISO27001": ["A.13.1.1", "A.13.1.3"],
        "NIST_CSF": ["PR.AC-5"], "HIPAA": ["§164.312(e)(1)"],
    },
    "identity_and_access.authorization.database_roles": {
        "SOC2_CC": ["CC6.1", "CC6.3"], "ISO27001": ["A.9.2.3"],
        "NIST_CSF": ["PR.AC-4"], "HIPAA": ["§164.312(a)(1)"],
    },
    "detection_and_response.logging.audit_logging": {
        "SOC2_CC": ["CC7.1", "CC7.2", "CC7.3"], "ISO27001": ["A.12.4.1"],
        "NIST_CSF": ["DE.AE-3"], "HIPAA": ["§164.312(b)"],
    },
    "data_protection.realtime.channel_access": {
        "SOC2_CC": ["CC6.1", "CC6.7"], "ISO27001": ["A.13.1.1"],
        "NIST_CSF": ["PR.DS-2"],
    },
}

def get_framework_mapping(domain_path: str) -> dict[str, list[str]]:
    return FRAMEWORK_MAPPINGS.get(domain_path, {})
