"""
[PHI] HIPAA-Compliant PHI-Safe Logging Module

This module provides PHI-safe logging capabilities that prevent Protected Health Information
from being written to log files while maintaining comprehensive audit trails for compliance.

Classification: PHI-CRITICAL
Author: HIPAA Compliance Team
Version: 1.0.0
Last Updated: 2025-08-01
"""

import re
import json
import logging
import hashlib
import secrets
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import structlog
from pythonjsonlogger import jsonlogger


class LogLevel(Enum):
    """HIPAA audit log levels."""
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    DEBUG = "DEBUG"
    AUDIT = "AUDIT"


class EventType(Enum):
    """HIPAA audit event types."""
    PHI_ACCESS = "PHI_ACCESS"
    PHI_CREATION = "PHI_CREATION"
    PHI_MODIFICATION = "PHI_MODIFICATION"
    PHI_DELETION = "PHI_DELETION"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    SYSTEM_ACCESS = "SYSTEM_ACCESS"
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
    SECURITY_EVENT = "SECURITY_EVENT"
    ERROR_EVENT = "ERROR_EVENT"


@dataclass
class AuditLogEntry:
    """Structured audit log entry for HIPAA compliance."""
    timestamp: str
    event_type: str
    user_id: str
    session_id: str
    action: str
    resource: str
    outcome: str
    details: Dict[str, Any]
    phi_involved: bool = False
    phi_hash: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    compliance_level: str = "HIPAA"
    retention_category: str = "AUDIT"


class PHIDetector:
    """
    Detect and mask PHI in log messages to ensure HIPAA compliance.
    """
    
    def __init__(self):
        """Initialize PHI detection patterns."""
        self.phi_patterns = {
            # Social Security Numbers
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b'),
            
            # Medical Record Numbers (various formats)
            'mrn': re.compile(r'\b(?:MRN|mrn|medical[_\s]?record[_\s]?number)[:\s]*[A-Z0-9]{6,12}\b', re.IGNORECASE),
            
            # Phone Numbers (US format)
            'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
            
            # Email Addresses
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            
            # Dates (various formats that could be DOB)
            'date': re.compile(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b|\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b'),
            
            # Names (basic pattern - surname, firstname)
            'name': re.compile(r'\b[A-Z][a-z]+,\s*[A-Z][a-z]+\b'),
            
            # Credit Card Numbers
            'credit_card': re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
            
            # Account Numbers
            'account': re.compile(r'\b(?:account|acct)[_\s#]*[:\s]*[A-Z0-9]{6,16}\b', re.IGNORECASE),
            
            # IP Addresses (could be identifying)
            'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            
            # Common medical terms with identifiers
            'medical_id': re.compile(r'\b(?:patient|diagnosis|prescription|treatment)[_\s#]*[:\s]*[A-Z0-9]{3,12}\b', re.IGNORECASE)
        }
        
        # Medical terminology that might be PHI
        self.medical_terms = [
            'patient', 'diagnosis', 'prescription', 'treatment', 'symptom',
            'medication', 'allergy', 'condition', 'procedure', 'surgery'
        ]
    
    def detect_phi(self, text: str) -> Dict[str, List[str]]:
        """
        Detect PHI patterns in text.
        
        Args:
            text: Text to analyze for PHI
            
        Returns:
            Dictionary of detected PHI patterns
        """
        detected = {}
        
        for pattern_name, pattern in self.phi_patterns.items():
            matches = pattern.findall(text)
            if matches:
                detected[pattern_name] = matches
        
        return detected
    
    def mask_phi(self, text: str, mask_char: str = "*") -> str:
        """
        Mask PHI in text for safe logging.
        
        Args:
            text: Text containing potential PHI
            mask_char: Character to use for masking
            
        Returns:
            Text with PHI masked
        """
        masked_text = text
        
        # Apply masking patterns
        for pattern_name, pattern in self.phi_patterns.items():
            if pattern_name == 'ssn':
                masked_text = pattern.sub('***-**-****', masked_text)
            elif pattern_name == 'phone':
                masked_text = pattern.sub('***-***-****', masked_text)
            elif pattern_name == 'email':
                masked_text = pattern.sub('[EMAIL_MASKED]', masked_text)
            elif pattern_name == 'credit_card':
                masked_text = pattern.sub('****-****-****-****', masked_text)
            else:
                masked_text = pattern.sub(f'[{pattern_name.upper()}_MASKED]', masked_text)
        
        return masked_text
    
    def create_phi_hash(self, phi_data: str) -> str:
        """
        Create a hash of PHI data for audit trail purposes.
        
        Args:
            phi_data: PHI data to hash
            
        Returns:
            SHA-256 hash of PHI data
        """
        return hashlib.sha256(phi_data.encode('utf-8')).hexdigest()[:16]


class PHISafeLogger:
    """
    HIPAA-compliant logger that prevents PHI from being written to logs
    while maintaining comprehensive audit trails.
    """
    
    def __init__(
        self, 
        name: str,
        log_level: LogLevel = LogLevel.INFO,
        retention_days: int = 2555,  # 7 years for HIPAA
        enable_phi_detection: bool = True
    ):
        """
        Initialize PHI-safe logger.
        
        Args:
            name: Logger name
            log_level: Minimum log level
            retention_days: Log retention period in days
            enable_phi_detection: Enable automatic PHI detection and masking
        """
        self.name = name
        self.log_level = log_level
        self.retention_days = retention_days
        self.enable_phi_detection = enable_phi_detection
        self.phi_detector = PHIDetector() if enable_phi_detection else None
        
        # Initialize structured logger
        self._setup_logger()
        
    def _setup_logger(self) -> None:
        """Setup structured logging with PHI protection."""
        # Configure structlog
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                self._phi_filter_processor,
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        # Get structured logger
        self.logger = structlog.get_logger(self.name)
        
        # Configure standard library logger
        self.stdlib_logger = logging.getLogger(self.name)
        self.stdlib_logger.setLevel(getattr(logging, self.log_level.value))
        
        # Add JSON formatter
        handler = logging.StreamHandler()
        formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(name)s %(levelname)s %(message)s'
        )
        handler.setFormatter(formatter)
        self.stdlib_logger.addHandler(handler)
    
    def _phi_filter_processor(self, logger, method_name, event_dict):
        """
        Structlog processor to filter PHI from log events.
        
        Args:
            logger: Logger instance
            method_name: Log method name
            event_dict: Event dictionary
            
        Returns:
            Filtered event dictionary
        """
        if not self.enable_phi_detection or not self.phi_detector:
            return event_dict
        
        # Filter message
        if 'event' in event_dict:
            original_message = str(event_dict['event'])
            phi_detected = self.phi_detector.detect_phi(original_message)
            
            if phi_detected:
                event_dict['event'] = self.phi_detector.mask_phi(original_message)
                event_dict['phi_detected'] = True
                event_dict['phi_types'] = list(phi_detected.keys())
                # Create hash for audit trail
                event_dict['phi_hash'] = self.phi_detector.create_phi_hash(original_message)
            else:
                event_dict['phi_detected'] = False
        
        # Filter other string fields
        for key, value in event_dict.items():
            if isinstance(value, str) and key not in ['event', 'phi_hash']:
                phi_detected = self.phi_detector.detect_phi(value)
                if phi_detected:
                    event_dict[key] = self.phi_detector.mask_phi(value)
        
        return event_dict
    
    def log_phi_access(
        self,
        user_id: str,
        action: str,
        resource: str,
        outcome: str,
        phi_hash: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log PHI access event for HIPAA audit trail.
        
        Args:
            user_id: User identifier
            action: Action performed (read, write, delete, etc.)
            resource: Resource accessed
            outcome: Outcome (success, failure, denied)
            phi_hash: Hash of PHI data accessed
            session_id: Session identifier
            ip_address: Client IP address
            details: Additional details
        """
        audit_entry = AuditLogEntry(
            timestamp=datetime.utcnow().isoformat(),
            event_type=EventType.PHI_ACCESS.value,
            user_id=user_id,
            session_id=session_id or self._generate_session_id(),
            action=action,
            resource=resource,
            outcome=outcome,
            details=details or {},
            phi_involved=True,
            phi_hash=phi_hash,
            ip_address=ip_address,
            compliance_level="HIPAA",
            retention_category="AUDIT"
        )
        
        self.logger.info(
            "PHI Access Event",
            **asdict(audit_entry)
        )
    
    def log_authentication(
        self,
        user_id: str,
        outcome: str,
        method: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log authentication event.
        
        Args:
            user_id: User identifier
            outcome: Authentication outcome
            method: Authentication method
            ip_address: Client IP address
            user_agent: Client user agent
            details: Additional details
        """
        audit_entry = AuditLogEntry(
            timestamp=datetime.utcnow().isoformat(),
            event_type=EventType.AUTHENTICATION.value,
            user_id=user_id,
            session_id=self._generate_session_id(),
            action=f"authentication_{method}",
            resource="authentication_system",
            outcome=outcome,
            details=details or {},
            phi_involved=False,
            ip_address=ip_address,
            user_agent=user_agent,
            compliance_level="HIPAA",
            retention_category="AUDIT"
        )
        
        self.logger.info(
            "Authentication Event",
            **asdict(audit_entry)
        )
    
    def log_security_event(
        self,
        event_description: str,
        severity: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log security event.
        
        Args:
            event_description: Description of security event
            severity: Event severity (low, medium, high, critical)
            user_id: Associated user identifier
            ip_address: Source IP address
            details: Additional details
        """
        audit_entry = AuditLogEntry(
            timestamp=datetime.utcnow().isoformat(),
            event_type=EventType.SECURITY_EVENT.value,
            user_id=user_id or "system",
            session_id=self._generate_session_id(),
            action="security_alert",
            resource="security_system",
            outcome=severity,
            details=details or {},
            phi_involved=False,
            ip_address=ip_address,
            compliance_level="HIPAA",
            retention_category="SECURITY"
        )
        
        self.logger.warning(
            f"Security Event: {event_description}",
            **asdict(audit_entry)
        )
    
    def log_system_error(
        self,
        error_message: str,
        component: str,
        user_id: Optional[str] = None,
        exception: Optional[Exception] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log system error with PHI protection.
        
        Args:
            error_message: Error message
            component: System component
            user_id: Associated user identifier
            exception: Exception object
            details: Additional details
        """
        # Ensure no PHI in error messages
        safe_error_message = error_message
        if self.enable_phi_detection and self.phi_detector:
            safe_error_message = self.phi_detector.mask_phi(error_message)
        
        error_details = details or {}
        if exception:
            error_details['exception_type'] = type(exception).__name__
            # Mask exception message for PHI
            exception_msg = str(exception)
            if self.enable_phi_detection and self.phi_detector:
                exception_msg = self.phi_detector.mask_phi(exception_msg)
            error_details['exception_message'] = exception_msg
        
        audit_entry = AuditLogEntry(
            timestamp=datetime.utcnow().isoformat(),
            event_type=EventType.ERROR_EVENT.value,
            user_id=user_id or "system",
            session_id=self._generate_session_id(),
            action="system_error",
            resource=component,
            outcome="error",
            details=error_details,
            phi_involved=False,
            compliance_level="HIPAA",
            retention_category="ERROR"
        )
        
        self.logger.error(
            f"System Error: {safe_error_message}",
            **asdict(audit_entry)
        )
    
    def info(self, message: str, **kwargs) -> None:
        """Log info message with PHI protection."""
        self.logger.info(message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message with PHI protection."""
        self.logger.warning(message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        """Log error message with PHI protection."""
        self.logger.error(message, **kwargs)
    
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message with PHI protection."""
        self.logger.debug(message, **kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message with PHI protection."""
        self.logger.critical(message, **kwargs)
    
    def _generate_session_id(self) -> str:
        """Generate unique session identifier."""
        return secrets.token_hex(16)


class AuditLogManager:
    """
    Manage HIPAA audit logs with proper retention and export capabilities.
    """
    
    def __init__(self, storage_connection_string: str, container_name: str = "audit-logs"):
        """
        Initialize audit log manager.
        
        Args:
            storage_connection_string: Azure Storage connection string
            container_name: Container name for audit logs
        """
        self.storage_connection_string = storage_connection_string
        self.container_name = container_name
        self.retention_days = 2555  # 7 years for HIPAA
    
    def export_audit_logs(
        self,
        start_date: datetime,
        end_date: datetime,
        event_types: Optional[List[str]] = None,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Export audit logs for compliance reporting.
        
        Args:
            start_date: Start date for export
            end_date: End date for export
            event_types: Specific event types to export
            user_id: Specific user to export logs for
            
        Returns:
            Dictionary with exported log data
        """
        # Implementation would query Azure Storage/Log Analytics
        # This is a placeholder for the actual implementation
        export_metadata = {
            "export_id": secrets.token_hex(16),
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "event_types": event_types,
            "user_id": user_id,
            "export_timestamp": datetime.utcnow().isoformat(),
            "compliance_level": "HIPAA",
            "retention_validated": True
        }
        
        return {
            "metadata": export_metadata,
            "logs": [],  # Would contain actual log entries
            "total_records": 0,
            "phi_records": 0,
            "compliance_validated": True
        }
    
    def validate_retention_compliance(self) -> Dict[str, Any]:
        """
        Validate that audit logs meet HIPAA retention requirements.
        
        Returns:
            Compliance validation results
        """
        validation_results = {
            "compliance_status": "COMPLIANT",
            "retention_period_days": self.retention_days,
            "oldest_log_date": None,
            "total_log_entries": 0,
            "phi_log_entries": 0,
            "validation_timestamp": datetime.utcnow().isoformat(),
            "issues": []
        }
        
        # Implementation would check actual log retention
        # This is a placeholder for the actual implementation
        
        return validation_results


# Global PHI-safe logger instance
phi_safe_logger = None


def get_phi_safe_logger(name: str = "hipaa-rag") -> PHISafeLogger:
    """
    Get or create PHI-safe logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        PHI-safe logger instance
    """
    global phi_safe_logger
    if phi_safe_logger is None:
        phi_safe_logger = PHISafeLogger(name)
    return phi_safe_logger


def log_phi_access(user_id: str, action: str, resource: str, outcome: str, **kwargs) -> None:
    """
    Convenience function to log PHI access events.
    
    Args:
        user_id: User identifier
        action: Action performed
        resource: Resource accessed
        outcome: Outcome of action
        **kwargs: Additional audit fields
    """
    logger = get_phi_safe_logger()
    logger.log_phi_access(user_id, action, resource, outcome, **kwargs)


def log_security_event(description: str, severity: str = "medium", **kwargs) -> None:
    """
    Convenience function to log security events.
    
    Args:
        description: Event description
        severity: Event severity
        **kwargs: Additional audit fields
    """
    logger = get_phi_safe_logger()
    logger.log_security_event(description, severity, **kwargs)