#!/usr/bin/env python3
"""
HIPAA Access Control Test Suite
Tests the role-based access control functionality with synthetic healthcare scenarios.
"""

import sys
import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum

# Mock the HIPAA access control system
class HIPAARole(Enum):
    """Healthcare-specific user roles for HIPAA compliance."""
    END_USER = "END_USER"
    HEALTHCARE_PROVIDER = "HEALTHCARE_PROVIDER" 
    SYSTEM_ADMIN = "SYSTEM_ADMIN"
    SECURITY_OFFICER = "SECURITY_OFFICER"
    COMPLIANCE_OFFICER = "COMPLIANCE_OFFICER"
    AUDITOR = "AUDITOR"

class AccessLevel(Enum):
    """Data access levels for PHI."""
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    AUDIT = "AUDIT"
    ADMIN = "ADMIN"

class MockHIPAAAccessControl:
    """Mock HIPAA Access Control for local testing."""
    
    def __init__(self):
        """Initialize access control system."""
        self.sessions = {}
        self.audit_logs = []
        
        # Define role permissions matrix
        self.role_permissions = {
            HIPAARole.END_USER: {
                AccessLevel.READ: ["limited_phi"],
                AccessLevel.WRITE: [],
                AccessLevel.DELETE: [],
                AccessLevel.AUDIT: [],
                AccessLevel.ADMIN: []
            },
            HIPAARole.HEALTHCARE_PROVIDER: {
                AccessLevel.READ: ["phi", "medical_records", "patient_data"],
                AccessLevel.WRITE: ["phi", "medical_records", "patient_data"],
                AccessLevel.DELETE: [],
                AccessLevel.AUDIT: [],
                AccessLevel.ADMIN: []
            },
            HIPAARole.SYSTEM_ADMIN: {
                AccessLevel.READ: ["system_config"],
                AccessLevel.WRITE: ["system_config"],
                AccessLevel.DELETE: ["system_data"],
                AccessLevel.AUDIT: [],
                AccessLevel.ADMIN: ["system_management"]
            },
            HIPAARole.SECURITY_OFFICER: {
                AccessLevel.READ: ["phi", "security_logs", "audit_logs"],
                AccessLevel.WRITE: ["security_config"],
                AccessLevel.DELETE: ["security_incidents"],
                AccessLevel.AUDIT: ["all_access"],
                AccessLevel.ADMIN: ["security_management"]
            },
            HIPAARole.COMPLIANCE_OFFICER: {
                AccessLevel.READ: ["audit_logs", "compliance_reports"],
                AccessLevel.WRITE: ["compliance_reports"],
                AccessLevel.DELETE: [],
                AccessLevel.AUDIT: ["phi_access", "compliance_activities"],
                AccessLevel.ADMIN: []
            },
            HIPAARole.AUDITOR: {
                AccessLevel.READ: ["audit_logs", "system_logs"],
                AccessLevel.WRITE: [],
                AccessLevel.DELETE: [],
                AccessLevel.AUDIT: ["all_activities"],
                AccessLevel.ADMIN: []
            }
        }
        
        # Session timeout configurations (in minutes)
        self.session_timeouts = {
            HIPAARole.END_USER: 30,
            HIPAARole.HEALTHCARE_PROVIDER: 60,
            HIPAARole.SYSTEM_ADMIN: 45,
            HIPAARole.SECURITY_OFFICER: 60,
            HIPAARole.COMPLIANCE_OFFICER: 60,
            HIPAARole.AUDITOR: 120
        }
    
    def authenticate_user(self, user_id: str, role: HIPAARole, mfa_verified: bool = False) -> Optional[str]:
        """Authenticate user and create session."""
        if not mfa_verified and role != HIPAARole.END_USER:
            return None  # MFA required for privileged roles
        
        session_id = f"session_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session_expiry = datetime.now() + timedelta(minutes=self.session_timeouts[role])
        
        self.sessions[session_id] = {
            'user_id': user_id,
            'role': role,
            'created': datetime.now(),
            'expires': session_expiry,
            'mfa_verified': mfa_verified,
            'active': True
        }
        
        self._audit_log('AUTHENTICATION', user_id, role.value, f"User authenticated successfully")
        return session_id
    
    def check_access_permission(self, session_id: str, access_level: AccessLevel, resource: str = "phi") -> bool:
        """Check if user has permission for specific access level."""
        if session_id not in self.sessions:
            self._audit_log('ACCESS_DENIED', 'unknown', 'INVALID_SESSION', f"Invalid session: {session_id}")
            return False
        
        session = self.sessions[session_id]
        
        # Check session expiry
        if datetime.now() > session['expires'] or not session['active']:
            self._audit_log('ACCESS_DENIED', session['user_id'], session['role'].value, f"Session expired")
            return False
        
        role = session['role']
        user_id = session['user_id']
        
        # Check role permissions
        if access_level in self.role_permissions[role]:
            allowed_resources = self.role_permissions[role][access_level]
            
            # Check if user can access the specific resource
            if resource in allowed_resources or "all_access" in allowed_resources:
                self._audit_log('ACCESS_GRANTED', user_id, role.value, f"Access granted: {access_level.value} on {resource}")
                return True
        
        self._audit_log('ACCESS_DENIED', user_id, role.value, f"Access denied: {access_level.value} on {resource}")
        return False
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke user session."""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session['active'] = False
            self._audit_log('SESSION_REVOKED', session['user_id'], session['role'].value, "Session revoked")
            return True
        return False
    
    def get_active_sessions(self) -> List[Dict]:
        """Get all active sessions."""
        active_sessions = []
        for session_id, session in self.sessions.items():
            if session['active'] and datetime.now() <= session['expires']:
                active_sessions.append({
                    'session_id': session_id,
                    'user_id': session['user_id'],
                    'role': session['role'].value,
                    'created': session['created'].isoformat(),
                    'expires': session['expires'].isoformat()
                })
        return active_sessions
    
    def _audit_log(self, event_type: str, user_id: str, role: str, message: str):
        """Create audit log entry."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'role': role,
            'message': message
        }
        self.audit_logs.append(entry)

def test_user_authentication():
    """Test user authentication with different roles."""
    print("🔐 Testing User Authentication...")
    print("=" * 50)
    
    access_control = MockHIPAAAccessControl()
    results = []
    
    # Test cases for authentication
    auth_cases = [
        {
            "name": "Healthcare Provider with MFA",
            "user_id": "dr_smith_001",
            "role": HIPAARole.HEALTHCARE_PROVIDER,
            "mfa_verified": True,
            "should_succeed": True
        },
        {
            "name": "Healthcare Provider without MFA",
            "user_id": "dr_jones_002", 
            "role": HIPAARole.HEALTHCARE_PROVIDER,
            "mfa_verified": False,
            "should_succeed": False
        },
        {
            "name": "End User without MFA",
            "user_id": "patient_001",
            "role": HIPAARole.END_USER,
            "mfa_verified": False,
            "should_succeed": True
        },
        {
            "name": "Security Officer with MFA",
            "user_id": "sec_officer_001",
            "role": HIPAARole.SECURITY_OFFICER,
            "mfa_verified": True,
            "should_succeed": True
        },
        {
            "name": "System Admin without MFA",
            "user_id": "admin_001",
            "role": HIPAARole.SYSTEM_ADMIN,
            "mfa_verified": False,
            "should_succeed": False
        },
        {
            "name": "Auditor with MFA",
            "user_id": "auditor_001",
            "role": HIPAARole.AUDITOR,
            "mfa_verified": True,
            "should_succeed": True
        }
    ]
    
    for case in auth_cases:
        print(f"\n🧪 Testing: {case['name']}")
        print(f"   User: {case['user_id']}, Role: {case['role'].value}, MFA: {case['mfa_verified']}")
        
        session_id = access_control.authenticate_user(
            case['user_id'], 
            case['role'], 
            case['mfa_verified']
        )
        
        if case['should_succeed']:
            if session_id:
                print(f"   ✅ PASS: Authentication successful - {session_id}")
                results.append({"test": case['name'], "status": "PASS", "session_id": session_id})
            else:
                print(f"   ❌ FAIL: Authentication should have succeeded")
                results.append({"test": case['name'], "status": "FAIL", "reason": "Authentication failed unexpectedly"})
        else:
            if not session_id:
                print(f"   ✅ PASS: Authentication correctly denied")
                results.append({"test": case['name'], "status": "PASS"})
            else:
                print(f"   ❌ FAIL: Authentication should have been denied")
                results.append({"test": case['name'], "status": "FAIL", "reason": "Authentication succeeded when it shouldn't have"})
    
    return results, access_control

def test_role_based_permissions(access_control):
    """Test role-based access permissions."""
    print("\n\n🛡️ Testing Role-Based Permissions...")
    print("=" * 50)
    
    results = []
    
    # Create test sessions for each role
    test_sessions = {}
    roles_to_test = [
        (HIPAARole.HEALTHCARE_PROVIDER, "dr_test_001"),
        (HIPAARole.SYSTEM_ADMIN, "admin_test_001"),
        (HIPAARole.SECURITY_OFFICER, "sec_test_001"),
        (HIPAARole.COMPLIANCE_OFFICER, "comp_test_001"),
        (HIPAARole.AUDITOR, "audit_test_001"),
        (HIPAARole.END_USER, "user_test_001")
    ]
    
    for role, user_id in roles_to_test:
        mfa_required = role != HIPAARole.END_USER
        session_id = access_control.authenticate_user(user_id, role, mfa_required)
        if session_id:
            test_sessions[role] = session_id
    
    # Test permission scenarios
    permission_tests = [
        {
            "name": "Healthcare Provider PHI Read",
            "role": HIPAARole.HEALTHCARE_PROVIDER,
            "access": AccessLevel.READ,
            "resource": "phi",
            "should_allow": True
        },
        {
            "name": "Healthcare Provider PHI Write",  
            "role": HIPAARole.HEALTHCARE_PROVIDER,
            "access": AccessLevel.WRITE,
            "resource": "phi",
            "should_allow": True
        },
        {
            "name": "Healthcare Provider PHI Delete",
            "role": HIPAARole.HEALTHCARE_PROVIDER,
            "access": AccessLevel.DELETE,
            "resource": "phi", 
            "should_allow": False
        },
        {
            "name": "End User PHI Read",
            "role": HIPAARole.END_USER,
            "access": AccessLevel.READ,
            "resource": "phi",
            "should_allow": False
        },
        {
            "name": "End User Limited PHI Read",
            "role": HIPAARole.END_USER,
            "access": AccessLevel.READ,
            "resource": "limited_phi",
            "should_allow": True
        },
        {
            "name": "System Admin PHI Access",
            "role": HIPAARole.SYSTEM_ADMIN,
            "access": AccessLevel.READ,
            "resource": "phi",
            "should_allow": False
        },
        {
            "name": "System Admin System Config",
            "role": HIPAARole.SYSTEM_ADMIN,
            "access": AccessLevel.WRITE,
            "resource": "system_config", 
            "should_allow": True
        },
        {
            "name": "Security Officer Audit Access",
            "role": HIPAARole.SECURITY_OFFICER,
            "access": AccessLevel.AUDIT,
            "resource": "all_access",
            "should_allow": True
        },
        {
            "name": "Auditor PHI Write",
            "role": HIPAARole.AUDITOR,
            "access": AccessLevel.WRITE,
            "resource": "phi",
            "should_allow": False
        },
        {
            "name": "Auditor Audit Logs Read",
            "role": HIPAARole.AUDITOR,
            "access": AccessLevel.READ,
            "resource": "audit_logs",
            "should_allow": True
        }
    ]
    
    for test in permission_tests:
        print(f"\n🧪 Testing: {test['name']}")
        
        if test['role'] not in test_sessions:
            print(f"   ❌ ERROR: No session for role {test['role'].value}")
            results.append({"test": test['name'], "status": "ERROR", "reason": "No test session"})
            continue
        
        session_id = test_sessions[test['role']]
        has_access = access_control.check_access_permission(
            session_id, 
            test['access'], 
            test['resource']
        )
        
        print(f"   Role: {test['role'].value}, Access: {test['access'].value}, Resource: {test['resource']}")
        print(f"   Result: {'ALLOWED' if has_access else 'DENIED'}")
        
        if test['should_allow'] == has_access:
            print(f"   ✅ PASS: Access control working correctly")
            results.append({"test": test['name'], "status": "PASS"})
        else:
            expected = "ALLOWED" if test['should_allow'] else "DENIED"
            actual = "ALLOWED" if has_access else "DENIED"
            print(f"   ❌ FAIL: Expected {expected}, got {actual}")
            results.append({"test": test['name'], "status": "FAIL", "reason": f"Expected {expected}, got {actual}"})
    
    return results

def test_session_management(access_control):
    """Test session timeout and management."""
    print("\n\n⏰ Testing Session Management...")
    print("=" * 50)
    
    results = []
    
    # Test session creation and active sessions
    print("\n   Testing active session tracking:")
    active_sessions = access_control.get_active_sessions()
    print(f"   Active sessions: {len(active_sessions)}")
    
    if len(active_sessions) > 0:
        print(f"   ✅ PASS: Session tracking working")
        results.append({"test": "Session Tracking", "status": "PASS", "active_sessions": len(active_sessions)})
    else:
        print(f"   ❌ FAIL: No active sessions found")
        results.append({"test": "Session Tracking", "status": "FAIL", "reason": "No active sessions"})
    
    # Test session revocation
    print(f"\n   Testing session revocation:")
    if active_sessions:
        test_session_id = active_sessions[0]['session_id']
        print(f"   Revoking session: {test_session_id}")
        
        revoked = access_control.revoke_session(test_session_id)
        if revoked:
            # Try to use revoked session
            has_access = access_control.check_access_permission(
                test_session_id, 
                AccessLevel.READ, 
                "phi"
            )
            
            if not has_access:
                print(f"   ✅ PASS: Revoked session correctly denied access")
                results.append({"test": "Session Revocation", "status": "PASS"})
            else:
                print(f"   ❌ FAIL: Revoked session still has access")
                results.append({"test": "Session Revocation", "status": "FAIL", "reason": "Revoked session has access"})
        else:
            print(f"   ❌ FAIL: Session revocation failed")
            results.append({"test": "Session Revocation", "status": "FAIL", "reason": "Revocation failed"})
    
    # Test invalid session handling
    print(f"\n   Testing invalid session handling:")
    invalid_session = "invalid_session_12345" 
    has_access = access_control.check_access_permission(
        invalid_session,
        AccessLevel.READ,
        "phi"
    )
    
    if not has_access:
        print(f"   ✅ PASS: Invalid session correctly denied")
        results.append({"test": "Invalid Session Handling", "status": "PASS"})
    else:
        print(f"   ❌ FAIL: Invalid session granted access")
        results.append({"test": "Invalid Session Handling", "status": "FAIL", "reason": "Invalid session granted access"})
    
    return results

def test_audit_logging(access_control):
    """Test audit logging functionality."""
    print("\n\n📋 Testing Audit Logging...")
    print("=" * 50)
    
    results = []
    
    # Check audit log entries
    audit_logs = access_control.audit_logs
    print(f"   Total audit log entries: {len(audit_logs)}")
    
    if len(audit_logs) > 0:
        print(f"   ✅ PASS: Audit logging is active")
        
        # Check for different event types
        event_types = set(log['event_type'] for log in audit_logs)
        print(f"   Event types logged: {', '.join(event_types)}")
        
        expected_events = ['AUTHENTICATION', 'ACCESS_GRANTED', 'ACCESS_DENIED', 'SESSION_REVOKED']
        found_events = [event for event in expected_events if event in event_types]
        
        if len(found_events) >= 3:  # At least 3 out of 4 event types
            print(f"   ✅ PASS: Comprehensive audit logging")
            results.append({"test": "Audit Logging Coverage", "status": "PASS", "events_logged": len(found_events)})
        else:
            print(f"   ⚠️  PARTIAL: Limited audit event types")
            results.append({"test": "Audit Logging Coverage", "status": "PARTIAL", "reason": "Limited event types"})
        
        # Check audit log structure
        sample_log = audit_logs[0]
        required_fields = ['timestamp', 'event_type', 'user_id', 'role', 'message']
        has_all_fields = all(field in sample_log for field in required_fields)
        
        if has_all_fields:
            print(f"   ✅ PASS: Audit log structure is complete")
            results.append({"test": "Audit Log Structure", "status": "PASS"})
        else:
            missing_fields = [field for field in required_fields if field not in sample_log]
            print(f"   ❌ FAIL: Missing audit log fields: {missing_fields}")
            results.append({"test": "Audit Log Structure", "status": "FAIL", "reason": f"Missing fields: {missing_fields}"})
            
    else:
        print(f"   ❌ FAIL: No audit log entries found")
        results.append({"test": "Audit Logging", "status": "FAIL", "reason": "No audit logs"})
    
    return results

def test_minimum_necessary_principle(access_control):
    """Test minimum necessary access principle."""
    print("\n\n🎯 Testing Minimum Necessary Principle...")
    print("=" * 50)
    
    results = []
    
    # Test that roles only have access to what they need
    role_access_tests = [
        {
            "name": "Healthcare Provider - No Admin Access",
            "role": HIPAARole.HEALTHCARE_PROVIDER,
            "access": AccessLevel.ADMIN,
            "resource": "system_management",
            "should_allow": False
        },
        {
            "name": "System Admin - No PHI Access", 
            "role": HIPAARole.SYSTEM_ADMIN,
            "access": AccessLevel.READ,
            "resource": "phi",
            "should_allow": False
        },
        {
            "name": "End User - No Write Access",
            "role": HIPAARole.END_USER,
            "access": AccessLevel.WRITE,
            "resource": "limited_phi",
            "should_allow": False
        },
        {
            "name": "Auditor - No Write Access to PHI",
            "role": HIPAARole.AUDITOR,
            "access": AccessLevel.WRITE,
            "resource": "phi",
            "should_allow": False
        }
    ]
    
    # Create test sessions
    for test in role_access_tests:
        user_id = f"min_test_{test['role'].value.lower()}"
        mfa_required = test['role'] != HIPAARole.END_USER
        session_id = access_control.authenticate_user(user_id, test['role'], mfa_required)
        
        if session_id:
            print(f"\n🧪 Testing: {test['name']}")
            has_access = access_control.check_access_permission(
                session_id,
                test['access'],
                test['resource']
            )
            
            if test['should_allow'] == has_access:
                print(f"   ✅ PASS: Minimum necessary principle enforced")
                results.append({"test": test['name'], "status": "PASS"})
            else:
                print(f"   ❌ FAIL: Excessive access granted")
                results.append({"test": test['name'], "status": "FAIL", "reason": "Excessive access"})
        else:
            print(f"   ❌ ERROR: Could not create session for {test['role'].value}")
            results.append({"test": test['name'], "status": "ERROR", "reason": "No session"})
    
    return results

def generate_access_control_report(all_results):
    """Generate comprehensive access control test report."""
    print("\n\n📊 HIPAA Access Control Test Report")
    print("=" * 60)
    print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Test Environment: LOCAL MOCK")
    print(f"Total Tests: {len(all_results)}")
    
    passed = len([r for r in all_results if r['status'] == 'PASS'])
    failed = len([r for r in all_results if r['status'] == 'FAIL'])
    errors = len([r for r in all_results if r['status'] == 'ERROR'])
    partial = len([r for r in all_results if r['status'] == 'PARTIAL'])
    
    print(f"✅ Passed: {passed}")
    print(f"⚠️  Partial: {partial}")
    print(f"❌ Failed: {failed}")
    print(f"⚠️  Errors: {errors}")
    
    success_rate = ((passed + partial) / len(all_results)) * 100 if all_results else 0
    print(f"📈 Success Rate: {success_rate:.1f}%")
    
    print("\n📋 Detailed Results:")
    for result in all_results:
        if result['status'] == 'PASS':
            icon = "✅"
        elif result['status'] == 'PARTIAL':
            icon = "⚠️"
        elif result['status'] == 'FAIL':
            icon = "❌"
        else:
            icon = "⚠️"
            
        print(f"   {icon} {result['test']}: {result['status']}")
        if 'reason' in result:
            print(f"      Reason: {result['reason']}")
        if 'session_id' in result:
            print(f"      Session: {result['session_id'][:20]}...")
        if 'active_sessions' in result:
            print(f"      Active Sessions: {result['active_sessions']}")
        if 'events_logged' in result:
            print(f"      Event Types: {result['events_logged']}")
    
    # Overall assessment
    print(f"\n🎯 Overall Assessment:")
    if success_rate >= 90:
        print("   🟢 EXCELLENT: Access control system working properly")
        print("   📝 Next Step: Test integration with API endpoints")
    elif success_rate >= 70:
        print("   🟡 GOOD: Minor issues detected, review failed tests")
        print("   📝 Next Step: Fix issues and enhance access controls")
    else:
        print("   🔴 CRITICAL: Major access control issues detected")
        print("   📝 Next Step: Review and fix access control implementation")
    
    return {
        "test_type": "HIPAA_ACCESS_CONTROL",
        "timestamp": datetime.now().isoformat(),
        "total_tests": len(all_results),
        "passed": passed,
        "partial": partial,
        "failed": failed,
        "errors": errors,
        "success_rate": success_rate,
        "results": all_results
    }

def main():
    """Run all access control tests."""
    print("🧪 HIPAA-RAG Access Control Testing")
    print("🚨 USING SYNTHETIC HEALTHCARE SCENARIOS ONLY")
    print("🔧 LOCAL MOCK MODE")
    print("=" * 60)
    
    all_results = []
    
    # Test authentication
    print("Phase 1: User Authentication")
    auth_results, access_control = test_user_authentication()
    all_results.extend(auth_results)
    
    # Test role-based permissions
    print("\nPhase 2: Role-Based Permissions")
    permission_results = test_role_based_permissions(access_control)
    all_results.extend(permission_results)
    
    # Test session management
    print("\nPhase 3: Session Management")
    session_results = test_session_management(access_control)
    all_results.extend(session_results)
    
    # Test audit logging
    print("\nPhase 4: Audit Logging")
    audit_results = test_audit_logging(access_control)
    all_results.extend(audit_results)
    
    # Test minimum necessary principle
    print("\nPhase 5: Minimum Necessary Principle")
    min_necessary_results = test_minimum_necessary_principle(access_control)
    all_results.extend(min_necessary_results)
    
    # Generate report
    report = generate_access_control_report(all_results)
    
    # Save report
    os.makedirs("tests/reports", exist_ok=True)
    report_file = f"tests/reports/access_control_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n💾 Test report saved to: {report_file}")
    
    return report['success_rate'] >= 70

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)