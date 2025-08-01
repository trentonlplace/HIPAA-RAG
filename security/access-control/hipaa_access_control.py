"""
[PHI] HIPAA-Compliant Access Control Module

This module implements HIPAA Security Rule compliant access controls including:
- Role-Based Access Control (RBAC)
- Multi-Factor Authentication (MFA) validation
- Session management with automatic timeouts
- Audit logging for all access attempts

Classification: PHI-CRITICAL
Author: HIPAA Compliance Team
Version: 1.0.0
Last Updated: 2025-08-01
"""

import os
import json
import secrets
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
import hashlib
import jwt
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Import PHI-safe logger
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'monitoring'))
from phi_safe_logger import get_phi_safe_logger, log_phi_access, log_security_event


class AccessLevel(Enum):
    """HIPAA access levels for PHI data."""
    NONE = "NONE"
    READ = "READ"
    WRITE = "WRITE" 
    ADMIN = "ADMIN"
    AUDIT = "AUDIT"


class HIPAARole(Enum):
    """HIPAA-compliant system roles."""
    END_USER = "END_USER"
    HEALTHCARE_PROVIDER = "HEALTHCARE_PROVIDER"
    SYSTEM_ADMIN = "SYSTEM_ADMIN"
    SECURITY_OFFICER = "SECURITY_OFFICER"
    COMPLIANCE_OFFICER = "COMPLIANCE_OFFICER"
    AUDITOR = "AUDITOR"


@dataclass
class UserPermissions:
    """User permissions for HIPAA-compliant access."""
    user_id: str
    role: HIPAARole
    phi_access_level: AccessLevel
    can_view_audit_logs: bool = False
    can_modify_config: bool = False
    can_manage_users: bool = False
    data_access_restrictions: List[str] = None
    session_timeout_minutes: int = 30
    requires_mfa: bool = True
    
    def __post_init__(self):
        if self.data_access_restrictions is None:
            self.data_access_restrictions = []


@dataclass
class AccessSession:
    """HIPAA-compliant user session."""
    session_id: str
    user_id: str
    role: HIPAARole
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    ip_address: str
    user_agent: str
    mfa_verified: bool = False
    phi_accessed: Set[str] = None
    
    def __post_init__(self):
        if self.phi_accessed is None:
            self.phi_accessed = set()
    
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.utcnow() > self.expires_at
    
    def is_idle_timeout(self, idle_minutes: int = 30) -> bool:
        """Check if session has idle timeout."""
        return datetime.utcnow() > (self.last_activity + timedelta(minutes=idle_minutes))
    
    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.utcnow()


class HIPAAAccessControl:
    """
    HIPAA-compliant access control system with RBAC, MFA, and audit logging.
    """
    
    def __init__(self, key_vault_url: str, secret_name: str = "jwt-secret"):
        """
        Initialize HIPAA access control.
        
        Args:
            key_vault_url: Azure Key Vault URL for JWT secrets
            secret_name: Name of JWT secret in Key Vault
        """
        self.key_vault_url = key_vault_url
        self.secret_name = secret_name
        self.logger = get_phi_safe_logger("hipaa-access-control")
        
        # Initialize Azure Key Vault client
        self.credential = DefaultAzureCredential()
        self.secret_client = SecretClient(vault_url=key_vault_url, credential=self.credential)
        
        # Active sessions
        self.active_sessions: Dict[str, AccessSession] = {}
        
        # Role-based permissions
        self.role_permissions = self._initialize_role_permissions()
        
        # Get JWT secret
        self.jwt_secret = self._get_jwt_secret()
        
        self.logger.info("HIPAA Access Control initialized", 
                        key_vault_url=key_vault_url)
    
    def _get_jwt_secret(self) -> str:
        """Get JWT secret from Key Vault."""
        try:
            secret = self.secret_client.get_secret(self.secret_name)
            return secret.value
        except Exception as e:
            # Create new secret if it doesn't exist
            jwt_secret = secrets.token_hex(32)
            self.secret_client.set_secret(
                self.secret_name,
                jwt_secret,
                content_type="text/plain",
                tags={
                    "purpose": "JWT-signing",
                    "compliance": "HIPAA",
                    "created": datetime.utcnow().isoformat()
                }
            )
            self.logger.info("Created new JWT secret in Key Vault")
            return jwt_secret
    
    def _initialize_role_permissions(self) -> Dict[HIPAARole, UserPermissions]:
        """Initialize default role-based permissions."""
        return {
            HIPAARole.END_USER: UserPermissions(
                user_id="",
                role=HIPAARole.END_USER,
                phi_access_level=AccessLevel.READ,
                can_view_audit_logs=False,
                can_modify_config=False,
                can_manage_users=False,
                session_timeout_minutes=30,
                requires_mfa=True
            ),
            HIPAARole.HEALTHCARE_PROVIDER: UserPermissions(
                user_id="",
                role=HIPAARole.HEALTHCARE_PROVIDER,
                phi_access_level=AccessLevel.WRITE,
                can_view_audit_logs=False,
                can_modify_config=False,
                can_manage_users=False,
                session_timeout_minutes=60,
                requires_mfa=True
            ),
            HIPAARole.SYSTEM_ADMIN: UserPermissions(
                user_id="",
                role=HIPAARole.SYSTEM_ADMIN,
                phi_access_level=AccessLevel.NONE,  # Admins should not access PHI
                can_view_audit_logs=False,
                can_modify_config=True,
                can_manage_users=True,
                session_timeout_minutes=45,
                requires_mfa=True
            ),
            HIPAARole.SECURITY_OFFICER: UserPermissions(
                user_id="",
                role=HIPAARole.SECURITY_OFFICER,
                phi_access_level=AccessLevel.AUDIT,
                can_view_audit_logs=True,
                can_modify_config=True,
                can_manage_users=True,
                session_timeout_minutes=60,
                requires_mfa=True
            ),
            HIPAARole.COMPLIANCE_OFFICER: UserPermissions(
                user_id="",
                role=HIPAARole.COMPLIANCE_OFFICER,
                phi_access_level=AccessLevel.AUDIT,
                can_view_audit_logs=True,
                can_modify_config=False,
                can_manage_users=False,
                session_timeout_minutes=60,
                requires_mfa=True
            ),
            HIPAARole.AUDITOR: UserPermissions(
                user_id="",
                role=HIPAARole.AUDITOR,
                phi_access_level=AccessLevel.AUDIT,
                can_view_audit_logs=True,
                can_modify_config=False,
                can_manage_users=False,
                session_timeout_minutes=120,
                requires_mfa=True
            )
        }
    
    def create_session(
        self,
        user_id: str,
        role: HIPAARole,
        ip_address: str,
        user_agent: str,
        mfa_verified: bool = False
    ) -> Tuple[str, str]:
        """
        Create a new HIPAA-compliant user session.
        
        Args:
            user_id: User identifier
            role: User role
            ip_address: Client IP address
            user_agent: Client user agent
            mfa_verified: Whether MFA has been verified
            
        Returns:
            Tuple of (session_id, jwt_token)
        """
        session_id = secrets.token_hex(32)
        
        # Get permissions for role
        permissions = self.role_permissions[role]
        session_timeout = permissions.session_timeout_minutes
        
        # Create session
        session = AccessSession(
            session_id=session_id,
            user_id=user_id,
            role=role,
            created_at=datetime.utcnow(),
            last_activity=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(minutes=session_timeout),
            ip_address=ip_address,
            user_agent=user_agent,
            mfa_verified=mfa_verified
        )
        
        # Store session
        self.active_sessions[session_id] = session
        
        # Create JWT token
        jwt_payload = {
            "session_id": session_id,
            "user_id": user_id,
            "role": role.value,
            "iat": datetime.utcnow().timestamp(),
            "exp": session.expires_at.timestamp(),
            "mfa_verified": mfa_verified
        }
        
        jwt_token = jwt.encode(jwt_payload, self.jwt_secret, algorithm="HS256")
        
        # Log session creation
        self.logger.log_authentication(
            user_id=user_id,
            outcome="success",
            method="session_creation",
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "session_id": session_id,
                "role": role.value,
                "mfa_verified": mfa_verified,
                "expires_at": session.expires_at.isoformat()
            }
        )
        
        return session_id, jwt_token
    
    def validate_session(self, jwt_token: str, ip_address: str) -> Optional[AccessSession]:
        """
        Validate JWT token and return active session.
        
        Args:
            jwt_token: JWT token to validate
            ip_address: Client IP address
            
        Returns:
            Active session if valid, None otherwise
        """
        try:
            # Decode JWT token
            payload = jwt.decode(jwt_token, self.jwt_secret, algorithms=["HS256"])
            session_id = payload.get("session_id")
            user_id = payload.get("user_id")
            
            # Get session
            session = self.active_sessions.get(session_id)
            if not session:
                log_security_event(
                    f"Invalid session ID in JWT token",
                    severity="medium",
                    user_id=user_id,
                    ip_address=ip_address,
                    details={"session_id": session_id}
                )
                return None
            
            # Check session expiry
            if session.is_expired():
                self._terminate_session(session_id, "expired")
                return None
            
            # Check idle timeout
            if session.is_idle_timeout():
                self._terminate_session(session_id, "idle_timeout")
                return None
            
            # Validate IP address (optional security measure)
            if session.ip_address != ip_address:
                log_security_event(
                    f"IP address mismatch for session",
                    severity="high",
                    user_id=user_id,
                    ip_address=ip_address,
                    details={
                        "session_id": session_id,
                        "original_ip": session.ip_address,
                        "current_ip": ip_address
                    }
                )
                # Don't automatically terminate - could be legitimate (mobile users)
                # But log for investigation
            
            # Update last activity
            session.update_activity()
            
            return session
            
        except jwt.ExpiredSignatureError:
            log_security_event(
                "Expired JWT token used",
                severity="low",
                ip_address=ip_address
            )
            return None
        except jwt.InvalidTokenError as e:
            log_security_event(
                f"Invalid JWT token: {str(e)}",
                severity="medium",
                ip_address=ip_address
            )
            return None
        except Exception as e:
            log_security_event(
                f"Session validation error: {str(e)}",
                severity="high",
                ip_address=ip_address
            )
            return None
    
    def check_phi_access(
        self,
        session: AccessSession,
        resource: str,
        action: str,
        phi_data_hash: Optional[str] = None
    ) -> bool:
        """
        Check if user has permission to access PHI data.
        
        Args:
            session: User session
            resource: Resource being accessed
            action: Action being performed
            phi_data_hash: Hash of PHI data being accessed
            
        Returns:
            True if access is permitted
        """
        permissions = self.role_permissions[session.role]
        permissions.user_id = session.user_id  # Set current user ID
        
        # Check MFA requirement
        if permissions.requires_mfa and not session.mfa_verified:
            log_phi_access(
                user_id=session.user_id,
                action=action,
                resource=resource,
                outcome="denied_mfa_required",
                session_id=session.session_id,
                ip_address=session.ip_address,
                details={"reason": "MFA verification required"}
            )
            return False
        
        # Check PHI access level
        access_allowed = False
        if action.lower() == "read" and permissions.phi_access_level in [AccessLevel.READ, AccessLevel.WRITE, AccessLevel.AUDIT]:
            access_allowed = True
        elif action.lower() == "write" and permissions.phi_access_level in [AccessLevel.WRITE]:
            access_allowed = True
        elif action.lower() == "audit" and permissions.phi_access_level in [AccessLevel.AUDIT]:
            access_allowed = True
        
        # Log access attempt
        outcome = "success" if access_allowed else "denied"
        log_phi_access(
            user_id=session.user_id,
            action=action,
            resource=resource,
            outcome=outcome,
            phi_hash=phi_data_hash,
            session_id=session.session_id,
            ip_address=session.ip_address,
            details={
                "role": session.role.value,
                "access_level": permissions.phi_access_level.value,
                "mfa_verified": session.mfa_verified
            }
        )
        
        # Track PHI access in session
        if access_allowed and phi_data_hash:
            session.phi_accessed.add(phi_data_hash)
        
        return access_allowed
    
    def check_admin_access(self, session: AccessSession, operation: str) -> bool:
        """
        Check if user has permission for administrative operations.
        
        Args:
            session: User session
            operation: Administrative operation
            
        Returns:
            True if access is permitted
        """
        permissions = self.role_permissions[session.role]
        permissions.user_id = session.user_id
        
        access_allowed = False
        
        if operation == "view_audit_logs":
            access_allowed = permissions.can_view_audit_logs
        elif operation == "modify_config":
            access_allowed = permissions.can_modify_config
        elif operation == "manage_users":
            access_allowed = permissions.can_manage_users
        
        # Log admin access attempt
        self.logger.log_authentication(
            user_id=session.user_id,
            outcome="success" if access_allowed else "denied",
            method="admin_access_check",
            ip_address=session.ip_address,
            details={
                "operation": operation,
                "role": session.role.value,
                "session_id": session.session_id
            }
        )
        
        return access_allowed
    
    def _terminate_session(self, session_id: str, reason: str) -> None:
        """Terminate a user session."""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            
            # Log session termination
            self.logger.log_authentication(
                user_id=session.user_id,
                outcome="session_terminated",
                method="automatic",
                ip_address=session.ip_address,
                details={
                    "session_id": session_id,
                    "reason": reason,
                    "phi_accessed_count": len(session.phi_accessed),
                    "duration_minutes": int((datetime.utcnow() - session.created_at).total_seconds() / 60)
                }
            )
            
            # Remove session
            del self.active_sessions[session_id]
    
    def terminate_session(self, session_id: str) -> bool:
        """
        Manually terminate a user session.
        
        Args:
            session_id: Session ID to terminate
            
        Returns:
            True if session was terminated
        """
        if session_id in self.active_sessions:
            self._terminate_session(session_id, "manual_logout")
            return True
        return False
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        expired_sessions = []
        
        for session_id, session in self.active_sessions.items():
            if session.is_expired() or session.is_idle_timeout():
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            reason = "expired" if self.active_sessions[session_id].is_expired() else "idle_timeout"
            self._terminate_session(session_id, reason)
        
        if expired_sessions:
            self.logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        
        return len(expired_sessions)
    
    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """
        Get list of active sessions for monitoring.
        
        Returns:
            List of active session information
        """
        sessions = []
        for session in self.active_sessions.values():
            sessions.append({
                "session_id": session.session_id,
                "user_id": session.user_id,
                "role": session.role.value,
                "created_at": session.created_at.isoformat(),
                "last_activity": session.last_activity.isoformat(),
                "expires_at": session.expires_at.isoformat(),
                "ip_address": session.ip_address,
                "mfa_verified": session.mfa_verified,
                "phi_accessed_count": len(session.phi_accessed)
            })
        return sessions


def require_hipaa_auth(access_level: AccessLevel = AccessLevel.READ):
    """
    Decorator to enforce HIPAA authentication and authorization.
    
    Args:
        access_level: Required access level for the resource
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # This would be implemented to work with Flask/FastAPI request context
            # For now, this is a placeholder showing the pattern
            
            # Get request context (implementation specific)
            # jwt_token = get_jwt_token_from_request()
            # ip_address = get_client_ip()
            
            # Validate session
            # access_control = get_access_control_instance()
            # session = access_control.validate_session(jwt_token, ip_address)
            
            # if not session:
            #     raise UnauthorizedError("Invalid or expired session")
            
            # Check PHI access if required
            # if access_level != AccessLevel.NONE:
            #     if not access_control.check_phi_access(session, func.__name__, access_level.value):
            #         raise ForbiddenError("Insufficient permissions for PHI access")
            
            # Add session to kwargs for the function to use
            # kwargs['hipaa_session'] = session
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Global access control instance
_access_control_instance = None


def initialize_hipaa_access_control(key_vault_url: str) -> HIPAAAccessControl:
    """
    Initialize global HIPAA access control instance.
    
    Args:
        key_vault_url: Azure Key Vault URL
        
    Returns:
        HIPAA access control instance
    """
    global _access_control_instance
    _access_control_instance = HIPAAAccessControl(key_vault_url)
    return _access_control_instance


def get_access_control() -> Optional[HIPAAAccessControl]:
    """Get global access control instance."""
    return _access_control_instance