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
}

def get_framework_mapping(domain_path: str) -> dict[str, list[str]]:
    return FRAMEWORK_MAPPINGS.get(domain_path, {})
