"""
[PHI] HIPAA-Compliant Configuration Helper Extension

This module extends the existing configuration system with HIPAA compliance controls,
encryption settings, and security configurations required for PHI handling.

Classification: PHI-CRITICAL
Author: HIPAA Compliance Team
Version: 1.0.0
Last Updated: 2025-08-01
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

# Import existing config components
from .config_helper import Config, ConfigHelper
from .embedding_config import EmbeddingConfig
from ..env_helper import EnvHelper

# Import HIPAA security components
import sys
security_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', '..', '..', 'security')
sys.path.append(security_path)

try:
    from encryption.hipaa_encryption_helper import PHIEncryptionHelper, PHIKeyManager
    from monitoring.phi_safe_logger import get_phi_safe_logger
    from access_control.hipaa_access_control import HIPAAAccessControl, HIPAARole, AccessLevel
except ImportError:
    # Fallback if HIPAA modules not available
    PHIEncryptionHelper = None
    PHIKeyManager = None
    get_phi_safe_logger = None
    HIPAAAccessControl = None


logger = logging.getLogger(__name__)


@dataclass
class HIPAASecurityConfig:
    """HIPAA security configuration settings."""
    encryption_enabled: bool = True
    customer_managed_keys: bool = True
    key_vault_url: str = ""
    phi_detection_enabled: bool = True
    audit_logging_enabled: bool = True
    mfa_required: bool = True
    session_timeout_minutes: int = 30
    private_endpoints_enabled: bool = True
    network_isolation_enabled: bool = True
    data_retention_days: int = 2555  # 7 years
    backup_retention_days: int = 35
    vulnerability_scanning_enabled: bool = True
    compliance_monitoring_enabled: bool = True


@dataclass
class PHIHandlingConfig:
    """PHI data handling configuration."""
    auto_classification: bool = True
    field_level_encryption: bool = True
    de_identification_enabled: bool = False
    minimum_necessary_enforcement: bool = True
    purpose_limitation_enabled: bool = True
    data_lineage_tracking: bool = True
    secure_deletion_enabled: bool = True
    phi_masking_in_logs: bool = True
    allowed_phi_operations: List[str] = None
    
    def __post_init__(self):
        if self.allowed_phi_operations is None:
            self.allowed_phi_operations = ["read", "write", "search", "analyze"]


@dataclass
class AuditConfig:
    """Audit and compliance configuration."""
    comprehensive_logging: bool = True
    real_time_monitoring: bool = True
    log_retention_days: int = 2555
    tamper_proof_logs: bool = True
    automatic_reporting: bool = True
    siem_integration: bool = True
    compliance_dashboard: bool = True
    risk_assessment_frequency_days: int = 90
    security_evaluation_frequency_days: int = 365


@dataclass
class NetworkSecurityConfig:
    """Network security configuration."""
    private_endpoints_only: bool = True
    vnet_isolation: bool = True
    waf_enabled: bool = True
    ddos_protection: bool = True
    tls_version: str = "1.3"
    certificate_pinning: bool = True
    network_segmentation: bool = True
    intrusion_detection: bool = True


class HIPAAConfigHelper(ConfigHelper):
    """
    Extended configuration helper with HIPAA compliance capabilities.
    
    Extends the existing ConfigHelper with security controls, encryption settings,
    and audit configurations required for PHI handling.
    """
    
    def __init__(self, config_client: Optional[Any] = None):
        """
        Initialize HIPAA configuration helper.
        
        Args:
            config_client: Configuration client (Azure Blob Storage client)
        """
        super().__init__(config_client)
        
        self.env_helper = EnvHelper()
        self.logger = get_phi_safe_logger("hipaa-config") if get_phi_safe_logger else logger
        
        # Initialize HIPAA-specific configurations
        self.hipaa_security_config = self._load_security_config()
        self.phi_handling_config = self._load_phi_handling_config()
        self.audit_config = self._load_audit_config()
        self.network_security_config = self._load_network_security_config()
        
        # Initialize encryption helper if available
        self.encryption_helper = None
        self.key_manager = None
        self.access_control = None
        
        if self.hipaa_security_config.key_vault_url:
            self._initialize_security_components()
    
    def _load_security_config(self) -> HIPAASecurityConfig:
        """Load HIPAA security configuration from environment variables."""
        return HIPAASecurityConfig(
            encryption_enabled=self.env_helper.get_env_var("HIPAA_ENCRYPTION_ENABLED", "true").lower() == "true",
            customer_managed_keys=self.env_helper.get_env_var("HIPAA_CUSTOMER_MANAGED_KEYS", "true").lower() == "true",
            key_vault_url=self.env_helper.get_env_var("AZURE_KEY_VAULT_URL", ""),
            phi_detection_enabled=self.env_helper.get_env_var("HIPAA_PHI_DETECTION_ENABLED", "true").lower() == "true",
            audit_logging_enabled=self.env_helper.get_env_var("HIPAA_AUDIT_LOGGING_ENABLED", "true").lower() == "true",
            mfa_required=self.env_helper.get_env_var("HIPAA_MFA_REQUIRED", "true").lower() == "true",
            session_timeout_minutes=int(self.env_helper.get_env_var("HIPAA_SESSION_TIMEOUT_MINUTES", "30")),
            private_endpoints_enabled=self.env_helper.get_env_var("HIPAA_PRIVATE_ENDPOINTS_ENABLED", "true").lower() == "true",
            network_isolation_enabled=self.env_helper.get_env_var("HIPAA_NETWORK_ISOLATION_ENABLED", "true").lower() == "true",
            data_retention_days=int(self.env_helper.get_env_var("HIPAA_DATA_RETENTION_DAYS", "2555")),
            backup_retention_days=int(self.env_helper.get_env_var("HIPAA_BACKUP_RETENTION_DAYS", "35")),
            vulnerability_scanning_enabled=self.env_helper.get_env_var("HIPAA_VULNERABILITY_SCANNING_ENABLED", "true").lower() == "true",
            compliance_monitoring_enabled=self.env_helper.get_env_var("HIPAA_COMPLIANCE_MONITORING_ENABLED", "true").lower() == "true"
        )
    
    def _load_phi_handling_config(self) -> PHIHandlingConfig:
        """Load PHI handling configuration."""
        return PHIHandlingConfig(
            auto_classification=self.env_helper.get_env_var("HIPAA_AUTO_CLASSIFICATION", "true").lower() == "true",
            field_level_encryption=self.env_helper.get_env_var("HIPAA_FIELD_LEVEL_ENCRYPTION", "true").lower() == "true",
            de_identification_enabled=self.env_helper.get_env_var("HIPAA_DE_IDENTIFICATION_ENABLED", "false").lower() == "true",
            minimum_necessary_enforcement=self.env_helper.get_env_var("HIPAA_MINIMUM_NECESSARY_ENFORCEMENT", "true").lower() == "true",
            purpose_limitation_enabled=self.env_helper.get_env_var("HIPAA_PURPOSE_LIMITATION_ENABLED", "true").lower() == "true",
            data_lineage_tracking=self.env_helper.get_env_var("HIPAA_DATA_LINEAGE_TRACKING", "true").lower() == "true",
            secure_deletion_enabled=self.env_helper.get_env_var("HIPAA_SECURE_DELETION_ENABLED", "true").lower() == "true",
            phi_masking_in_logs=self.env_helper.get_env_var("HIPAA_PHI_MASKING_IN_LOGS", "true").lower() == "true"
        )
    
    def _load_audit_config(self) -> AuditConfig:
        """Load audit and compliance configuration."""
        return AuditConfig(
            comprehensive_logging=self.env_helper.get_env_var("HIPAA_COMPREHENSIVE_LOGGING", "true").lower() == "true",
            real_time_monitoring=self.env_helper.get_env_var("HIPAA_REAL_TIME_MONITORING", "true").lower() == "true",
            log_retention_days=int(self.env_helper.get_env_var("HIPAA_LOG_RETENTION_DAYS", "2555")),
            tamper_proof_logs=self.env_helper.get_env_var("HIPAA_TAMPER_PROOF_LOGS", "true").lower() == "true",
            automatic_reporting=self.env_helper.get_env_var("HIPAA_AUTOMATIC_REPORTING", "true").lower() == "true",
            siem_integration=self.env_helper.get_env_var("HIPAA_SIEM_INTEGRATION", "true").lower() == "true",
            compliance_dashboard=self.env_helper.get_env_var("HIPAA_COMPLIANCE_DASHBOARD", "true").lower() == "true",
            risk_assessment_frequency_days=int(self.env_helper.get_env_var("HIPAA_RISK_ASSESSMENT_FREQUENCY_DAYS", "90")),
            security_evaluation_frequency_days=int(self.env_helper.get_env_var("HIPAA_SECURITY_EVALUATION_FREQUENCY_DAYS", "365"))
        )
    
    def _load_network_security_config(self) -> NetworkSecurityConfig:
        """Load network security configuration."""
        return NetworkSecurityConfig(
            private_endpoints_only=self.env_helper.get_env_var("HIPAA_PRIVATE_ENDPOINTS_ONLY", "true").lower() == "true",
            vnet_isolation=self.env_helper.get_env_var("HIPAA_VNET_ISOLATION", "true").lower() == "true",
            waf_enabled=self.env_helper.get_env_var("HIPAA_WAF_ENABLED", "true").lower() == "true",
            ddos_protection=self.env_helper.get_env_var("HIPAA_DDOS_PROTECTION", "true").lower() == "true",
            tls_version=self.env_helper.get_env_var("HIPAA_TLS_VERSION", "1.3"),
            certificate_pinning=self.env_helper.get_env_var("HIPAA_CERTIFICATE_PINNING", "true").lower() == "true",
            network_segmentation=self.env_helper.get_env_var("HIPAA_NETWORK_SEGMENTATION", "true").lower() == "true",
            intrusion_detection=self.env_helper.get_env_var("HIPAA_INTRUSION_DETECTION", "true").lower() == "true"
        )
    
    def _initialize_security_components(self) -> None:
        """Initialize HIPAA security components."""
        try:
            if PHIEncryptionHelper and self.hipaa_security_config.encryption_enabled:
                self.encryption_helper = PHIEncryptionHelper(self.hipaa_security_config.key_vault_url)
                
                # Validate encryption functionality
                if not self.encryption_helper.validate_encryption():
                    self.logger.error("Encryption validation failed - PHI encryption not available")
                    raise Exception("HIPAA encryption validation failed")
            
            if PHIKeyManager:
                self.key_manager = PHIKeyManager(self.hipaa_security_config.key_vault_url)
            
            if HIPAAAccessControl:
                self.access_control = HIPAAAccessControl(self.hipaa_security_config.key_vault_url)
            
            self.logger.info("HIPAA security components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize HIPAA security components: {e}")
            raise Exception(f"HIPAA security initialization failed: {e}")
    
    def get_encrypted_config(self, config_key: str) -> Optional[Dict[str, Any]]:
        """
        Get configuration with PHI fields encrypted.
        
        Args:
            config_key: Configuration key to retrieve
            
        Returns:
            Configuration with encrypted PHI fields
        """
        try:
            # Get base configuration
            config = self.get_config()
            
            if not self.encryption_helper or not config:
                return config
            
            # Encrypt sensitive configuration fields
            encrypted_config = self._encrypt_sensitive_fields(config, config_key)
            
            return encrypted_config
            
        except Exception as e:
            self.logger.error(f"Failed to get encrypted configuration: {e}")
            return None
    
    def _encrypt_sensitive_fields(self, config: Dict[str, Any], context: str) -> Dict[str, Any]:
        """
        Encrypt sensitive fields in configuration.
        
        Args:
            config: Configuration dictionary
            context: Context for encryption
            
        Returns:
            Configuration with encrypted sensitive fields
        """
        if not self.encryption_helper:
            return config
        
        encrypted_config = config.copy()
        
        # List of fields that may contain PHI or sensitive data
        sensitive_fields = [
            "api_keys", "connection_strings", "secrets", "passwords",
            "user_data", "patient_info", "medical_data", "personal_info"
        ]
        
        for field in sensitive_fields:
            if field in encrypted_config:
                try:
                    field_data = encrypted_config[field]
                    if isinstance(field_data, (str, dict)):
                        encrypted_field = self.encryption_helper.encrypt_field(
                            field_value=field_data,
                            field_name=field,
                            record_id=context
                        )
                        encrypted_config[field] = encrypted_field
                except Exception as e:
                    self.logger.error(f"Failed to encrypt field {field}: {e}")
        
        return encrypted_config
    
    def validate_hipaa_compliance(self) -> Dict[str, Any]:
        """
        Validate HIPAA compliance configuration.
        
        Returns:
            Compliance validation results
        """
        validation_results = {
            "overall_status": "COMPLIANT",
            "validation_timestamp": datetime.utcnow().isoformat(),
            "security_controls": {},
            "phi_handling": {},
            "audit_controls": {},
            "network_security": {},
            "issues": [],
            "recommendations": []
        }
        
        # Validate security controls
        validation_results["security_controls"] = self._validate_security_controls()
        
        # Validate PHI handling
        validation_results["phi_handling"] = self._validate_phi_handling()
        
        # Validate audit controls
        validation_results["audit_controls"] = self._validate_audit_controls()
        
        # Validate network security
        validation_results["network_security"] = self._validate_network_security()
        
        # Determine overall status
        all_validations = [
            validation_results["security_controls"],
            validation_results["phi_handling"],
            validation_results["audit_controls"],
            validation_results["network_security"]
        ]
        
        if any(not v.get("compliant", False) for v in all_validations):
            validation_results["overall_status"] = "NON_COMPLIANT"
        
        # Collect issues and recommendations
        for validation in all_validations:
            validation_results["issues"].extend(validation.get("issues", []))
            validation_results["recommendations"].extend(validation.get("recommendations", []))
        
        return validation_results
    
    def _validate_security_controls(self) -> Dict[str, Any]:
        """Validate security controls compliance."""
        issues = []
        recommendations = []
        
        if not self.hipaa_security_config.encryption_enabled:
            issues.append("Encryption is disabled - HIPAA requires PHI encryption")
        
        if not self.hipaa_security_config.customer_managed_keys:
            issues.append("Customer-managed keys not enabled - Required for HIPAA compliance")
        
        if not self.hipaa_security_config.key_vault_url:
            issues.append("Key Vault URL not configured - Required for secure key management")
        
        if not self.hipaa_security_config.mfa_required:
            issues.append("MFA not required - HIPAA recommends multi-factor authentication")
        
        if self.hipaa_security_config.session_timeout_minutes > 60:
            recommendations.append("Consider reducing session timeout to 30 minutes for enhanced security")
        
        return {
            "compliant": len(issues) == 0,
            "issues": issues,
            "recommendations": recommendations,
            "controls_enabled": {
                "encryption": self.hipaa_security_config.encryption_enabled,
                "customer_managed_keys": self.hipaa_security_config.customer_managed_keys,
                "mfa_required": self.hipaa_security_config.mfa_required,
                "private_endpoints": self.hipaa_security_config.private_endpoints_enabled,
                "network_isolation": self.hipaa_security_config.network_isolation_enabled
            }
        }
    
    def _validate_phi_handling(self) -> Dict[str, Any]:
        """Validate PHI handling compliance."""
        issues = []
        recommendations = []
        
        if not self.phi_handling_config.auto_classification:
            recommendations.append("Enable auto-classification for better PHI detection")
        
        if not self.phi_handling_config.field_level_encryption:
            issues.append("Field-level encryption disabled - Required for PHI protection")
        
        if not self.phi_handling_config.minimum_necessary_enforcement:
            issues.append("Minimum necessary standard not enforced - HIPAA requirement")
        
        if not self.phi_handling_config.purpose_limitation_enabled:
            issues.append("Purpose limitation not enabled - HIPAA requirement")
        
        if not self.phi_handling_config.phi_masking_in_logs:
            issues.append("PHI masking in logs disabled - Critical for log security")
        
        return {
            "compliant": len(issues) == 0,
            "issues": issues,
            "recommendations": recommendations,
            "phi_controls": {
                "field_level_encryption": self.phi_handling_config.field_level_encryption,
                "minimum_necessary": self.phi_handling_config.minimum_necessary_enforcement,
                "purpose_limitation": self.phi_handling_config.purpose_limitation_enabled,
                "phi_masking": self.phi_handling_config.phi_masking_in_logs
            }
        }
    
    def _validate_audit_controls(self) -> Dict[str, Any]:
        """Validate audit controls compliance."""
        issues = []
        recommendations = []
        
        if not self.audit_config.comprehensive_logging:
            issues.append("Comprehensive logging disabled - HIPAA requires audit controls")
        
        if self.audit_config.log_retention_days < 2555:  # 7 years
            issues.append("Log retention period less than 7 years - HIPAA requirement")
        
        if not self.audit_config.tamper_proof_logs:
            issues.append("Tamper-proof logs not enabled - Required for audit integrity")
        
        if not self.audit_config.real_time_monitoring:
            recommendations.append("Enable real-time monitoring for better security")
        
        return {
            "compliant": len(issues) == 0,
            "issues": issues,
            "recommendations": recommendations,
            "audit_controls": {
                "comprehensive_logging": self.audit_config.comprehensive_logging,
                "log_retention_days": self.audit_config.log_retention_days,
                "tamper_proof_logs": self.audit_config.tamper_proof_logs,
                "real_time_monitoring": self.audit_config.real_time_monitoring
            }
        }
    
    def _validate_network_security(self) -> Dict[str, Any]:
        """Validate network security compliance."""
        issues = []
        recommendations = []
        
        if not self.network_security_config.private_endpoints_only:
            issues.append("Private endpoints not enforced - Required for network isolation")
        
        if not self.network_security_config.vnet_isolation:
            issues.append("VNet isolation disabled - Required for network security")
        
        if self.network_security_config.tls_version != "1.3":
            recommendations.append("Upgrade to TLS 1.3 for enhanced security")
        
        if not self.network_security_config.waf_enabled:
            recommendations.append("Enable Web Application Firewall for additional protection")
        
        return {
            "compliant": len(issues) == 0,
            "issues": issues,
            "recommendations": recommendations,
            "network_controls": {
                "private_endpoints": self.network_security_config.private_endpoints_only,
                "vnet_isolation": self.network_security_config.vnet_isolation,
                "tls_version": self.network_security_config.tls_version,
                "waf_enabled": self.network_security_config.waf_enabled
            }
        }
    
    def get_compliance_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive HIPAA compliance report.
        
        Returns:
            Detailed compliance report
        """
        compliance_validation = self.validate_hipaa_compliance()
        
        report = {
            "report_id": f"hipaa-compliance-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.utcnow().isoformat(),
            "report_type": "HIPAA_COMPLIANCE_ASSESSMENT",
            "overall_status": compliance_validation["overall_status"],
            "compliance_score": self._calculate_compliance_score(compliance_validation),
            "validation_results": compliance_validation,
            "system_configuration": {
                "security_config": asdict(self.hipaa_security_config),
                "phi_handling_config": asdict(self.phi_handling_config),
                "audit_config": asdict(self.audit_config),
                "network_security_config": asdict(self.network_security_config)
            },
            "recommendations": {
                "immediate_actions": [issue for issue in compliance_validation["issues"]],
                "improvements": [rec for rec in compliance_validation["recommendations"]],
                "next_assessment_due": (datetime.utcnow() + timedelta(days=90)).isoformat()
            }
        }
        
        return report
    
    def _calculate_compliance_score(self, validation_results: Dict[str, Any]) -> float:
        """
        Calculate compliance score (0-100).
        
        Args:
            validation_results: Validation results
            
        Returns:
            Compliance score percentage
        """
        total_controls = 0
        compliant_controls = 0
        
        for category in ["security_controls", "phi_handling", "audit_controls", "network_security"]:
            if category in validation_results:
                total_controls += 1
                if validation_results[category].get("compliant", False):
                    compliant_controls += 1
        
        if total_controls == 0:
            return 0.0
        
        return (compliant_controls / total_controls) * 100
    
    def export_hipaa_configuration(self) -> Dict[str, Any]:
        """
        Export HIPAA configuration for documentation and audit purposes.
        
        Returns:
            Exportable configuration dictionary
        """
        return {
            "export_timestamp": datetime.utcnow().isoformat(),
            "configuration_version": "1.0.0",
            "hipaa_security_config": asdict(self.hipaa_security_config),
            "phi_handling_config": asdict(self.phi_handling_config),
            "audit_config": asdict(self.audit_config),
            "network_security_config": asdict(self.network_security_config),
            "compliance_status": self.validate_hipaa_compliance()["overall_status"],
            "encryption_status": {
                "encryption_helper_available": self.encryption_helper is not None,
                "key_manager_available": self.key_manager is not None,
                "access_control_available": self.access_control is not None
            }
        }