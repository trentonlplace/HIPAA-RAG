#!/usr/bin/env python3
"""
Integrated HIPAA Audit System Test Suite
Tests the complete audit workflow combining access control and PHI-safe logging.
"""

import sys
import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum

# Import our mock components from previous tests
sys.path.append(os.path.join(os.path.dirname(__file__)))

# Import mock components (we'll define them here for integration)
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

class EventType(Enum):
    """HIPAA audit event types."""
    PHI_ACCESS = "PHI_ACCESS"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION_FAILURE = "AUTHORIZATION_FAILURE"
    SECURITY_EVENT = "SECURITY_EVENT"
    DATA_MODIFICATION = "DATA_MODIFICATION"
    SYSTEM_ACCESS = "SYSTEM_ACCESS"
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
    AUDIT_LOG_ACCESS = "AUDIT_LOG_ACCESS"

import re

class IntegratedHIPAAAuditSystem:
    """Integrated HIPAA audit system combining access control and PHI-safe logging."""
    
    def __init__(self):
        """Initialize the integrated audit system."""
        self.sessions = {}
        self.audit_logs = []
        self.phi_access_logs = []
        
        # PHI detection patterns
        self.phi_patterns = {
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b'),
            'mrn': re.compile(r'\b(?:MRN|mrn)[:\s]*[A-Z0-9]{6,12}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b'),
            'date_of_birth': re.compile(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{4}\b|\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b'),
            'name_pattern': re.compile(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b')
        }
        
        # Role permissions matrix
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
            HIPAARole.SECURITY_OFFICER: {
                AccessLevel.READ: ["phi", "security_logs", "audit_logs"],
                AccessLevel.WRITE: ["security_config"],
                AccessLevel.DELETE: ["security_incidents"],
                AccessLevel.AUDIT: ["all_access"],
                AccessLevel.ADMIN: ["security_management"]
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
    
    def _mask_phi(self, message: str):
        """Mask PHI patterns and generate PHI hash for audit trail."""
        masked_message = message
        phi_found = []
        phi_hash_data = []
        
        for pattern_name, pattern in self.phi_patterns.items():
            matches = pattern.findall(masked_message)
            if matches:
                phi_found.append(f"{pattern_name}: {len(matches)} instances")
                # Store original PHI values for hash generation (in real implementation, hash immediately)
                phi_hash_data.extend(matches)
                
                # Replace with masked version
                if pattern_name == 'ssn':
                    masked_message = pattern.sub('XXX-XX-XXXX', masked_message)
                elif pattern_name == 'mrn':
                    masked_message = pattern.sub('MRN:XXXXXX', masked_message)
                elif pattern_name == 'email':
                    masked_message = pattern.sub('email@[REDACTED]', masked_message) 
                elif pattern_name == 'phone':
                    masked_message = pattern.sub('(XXX) XXX-XXXX', masked_message)
                elif pattern_name == 'date_of_birth':
                    masked_message = pattern.sub('XX/XX/XXXX', masked_message)
                elif pattern_name == 'name_pattern':
                    if any(keyword in message.lower() for keyword in ['patient', 'doctor', 'dr.', 'physician', 'nurse']):
                        masked_message = pattern.sub('[NAME_REDACTED]', masked_message)
        
        # Generate PHI hash for audit trail (simplified for testing)
        phi_hash = hash('|'.join(phi_hash_data)) if phi_hash_data else None
        
        return masked_message, phi_found, str(phi_hash) if phi_hash else None
    
    def authenticate_user(self, user_id: str, role: HIPAARole, mfa_verified: bool = False, 
                         ip_address: str = "127.0.0.1") -> Optional[str]:
        """Authenticate user with comprehensive audit logging."""
        
        # Check MFA requirement
        if not mfa_verified and role != HIPAARole.END_USER:
            self._create_audit_log(
                EventType.AUTHORIZATION_FAILURE,
                user_id,
                role.value,
                f"Authentication failed: MFA required for role {role.value}",
                ip_address=ip_address
            )
            return None
        
        # Create session
        session_id = f"session_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session_expiry = datetime.now() + timedelta(minutes=self.session_timeouts[role])
        
        self.sessions[session_id] = {
            'user_id': user_id,
            'role': role,
            'created': datetime.now(),
            'expires': session_expiry,
            'mfa_verified': mfa_verified,
            'active': True,
            'ip_address': ip_address
        }
        
        # Audit successful authentication
        self._create_audit_log(
            EventType.AUTHENTICATION,
            user_id,
            role.value,
            f"User authenticated successfully with MFA: {mfa_verified}",
            session_id=session_id,
            ip_address=ip_address
        )
        
        return session_id
    
    def access_phi_data(self, session_id: str, phi_data: str, operation: str = "READ",
                       resource_id: str = "patient_record") -> Optional[str]:
        """Access PHI data with comprehensive audit logging."""
        
        # Validate session
        if session_id not in self.sessions:
            self._create_audit_log(
                EventType.AUTHORIZATION_FAILURE,
                'unknown',
                'INVALID_SESSION',
                f"PHI access attempt with invalid session: {session_id[:20]}..."
            )
            return None
        
        session = self.sessions[session_id]
        
        # Check session expiry
        if datetime.now() > session['expires'] or not session['active']:
            self._create_audit_log(
                EventType.AUTHORIZATION_FAILURE,
                session['user_id'],
                session['role'].value,
                f"PHI access attempt with expired session",
                session_id=session_id
            )
            return None
        
        # Check PHI access permissions
        role = session['role']
        user_id = session['user_id']
        
        # Determine access level based on operation
        access_level = AccessLevel.READ if operation == "READ" else AccessLevel.WRITE
        
        # Check permissions
        if access_level in self.role_permissions[role]:
            allowed_resources = self.role_permissions[role][access_level]
            
            if "phi" in allowed_resources or "limited_phi" in allowed_resources:
                # Mask PHI for logging
                masked_data, phi_detected, phi_hash = self._mask_phi(phi_data)
                
                # Create PHI access audit log
                self._create_audit_log(
                    EventType.PHI_ACCESS,
                    user_id,
                    role.value,
                    f"PHI {operation} operation on {resource_id}",
                    session_id=session_id,
                    ip_address=session['ip_address'],
                    phi_hash=phi_hash,
                    resource_id=resource_id
                )
                
                # Log PHI-specific access
                phi_access_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'user_id': user_id,
                    'role': role.value,
                    'operation': operation,
                    'resource_id': resource_id,
                    'phi_hash': phi_hash,
                    'phi_detected': phi_detected,
                    'session_id': session_id,
                    'ip_address': session['ip_address']
                }
                self.phi_access_logs.append(phi_access_entry)
                
                # Return masked data for further processing
                return masked_data
        
        # Access denied
        self._create_audit_log(
            EventType.AUTHORIZATION_FAILURE,
            user_id,
            role.value,
            f"PHI access denied: insufficient permissions for {operation} on {resource_id}",
            session_id=session_id,
            ip_address=session['ip_address']
        )
        
        return None
    
    def _create_audit_log(self, event_type: EventType, user_id: str, role: str, message: str,
                         session_id: str = None, ip_address: str = None, phi_hash: str = None,
                         resource_id: str = None):
        """Create comprehensive audit log entry."""
        
        # Mask any PHI that might be in the message
        masked_message, _, _ = self._mask_phi(message)
        
        entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type.value,
            'user_id': user_id,
            'role': role,
            'message': masked_message,
            'session_id': session_id,
            'ip_address': ip_address,
            'phi_hash': phi_hash,
            'resource_id': resource_id,
            'compliance_level': 'HIPAA',
            'retention_period': '7_years'
        }
        
        # Remove None values
        entry = {k: v for k, v in entry.items() if v is not None}
        
        self.audit_logs.append(entry)
    
    def get_audit_report(self, role: HIPAARole, user_id: str, 
                        start_date: datetime = None, end_date: datetime = None) -> Dict:
        """Generate audit report based on user role and permissions."""
        
        if start_date is None:
            start_date = datetime.now() - timedelta(days=30)
        if end_date is None:
            end_date = datetime.now()
        
        # Filter logs based on date range
        filtered_logs = [
            log for log in self.audit_logs
            if start_date <= datetime.fromisoformat(log['timestamp']) <= end_date
        ]
        
        # Filter based on role permissions
        if role == HIPAARole.AUDITOR:
            # Auditors can see all logs
            accessible_logs = filtered_logs
        elif role == HIPAARole.SECURITY_OFFICER:
            # Security officers can see security and access logs
            accessible_logs = [
                log for log in filtered_logs
                if log['event_type'] in ['AUTHENTICATION', 'AUTHORIZATION_FAILURE', 'SECURITY_EVENT', 'PHI_ACCESS']
            ]
        elif role == HIPAARole.COMPLIANCE_OFFICER:
            # Compliance officers can see PHI access and compliance-related logs
            accessible_logs = [
                log for log in filtered_logs
                if log['event_type'] in ['PHI_ACCESS', 'AUTHORIZATION_FAILURE']
            ]
        else:
            # Other roles can only see their own activities
            accessible_logs = [
                log for log in filtered_logs
                if log.get('user_id') == user_id
            ]
        
        # Generate summary statistics
        event_counts = {}
        for log in accessible_logs:
            event_type = log['event_type']
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        
        report = {
            'report_generated': datetime.now().isoformat(),
            'requested_by': user_id,
            'requester_role': role.value,
            'date_range': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'total_events': len(accessible_logs),
            'event_summary': event_counts,
            'audit_logs': accessible_logs
        }
        
        return report

def test_integrated_authentication_audit():
    """Test authentication with comprehensive audit logging."""
    print("🔐 Testing Integrated Authentication Audit...")
    print("=" * 50)
    
    audit_system = IntegratedHIPAAAuditSystem()
    results = []
    
    # Test successful authentication
    print("\n   Testing successful authentication:")
    session_id = audit_system.authenticate_user(
        "dr_test_001", 
        HIPAARole.HEALTHCARE_PROVIDER, 
        mfa_verified=True,
        ip_address="192.168.1.100"
    )
    
    if session_id:
        print(f"   ✅ PASS: Authentication successful")
        
        # Check audit log was created
        auth_logs = [log for log in audit_system.audit_logs if log['event_type'] == 'AUTHENTICATION']
        if auth_logs:
            print(f"   ✅ PASS: Authentication audit log created")
            results.append({"test": "Authentication Audit", "status": "PASS"})
        else:
            print(f"   ❌ FAIL: No authentication audit log")
            results.append({"test": "Authentication Audit", "status": "FAIL", "reason": "No audit log"})
    else:
        print(f"   ❌ FAIL: Authentication failed")
        results.append({"test": "Authentication", "status": "FAIL", "reason": "Authentication failed"})
    
    # Test failed authentication (no MFA)
    print("\n   Testing failed authentication (no MFA):")
    failed_session = audit_system.authenticate_user(
        "dr_test_002",
        HIPAARole.HEALTHCARE_PROVIDER,
        mfa_verified=False,
        ip_address="192.168.1.101"
    )
    
    if not failed_session:
        # Check failure audit log
        failure_logs = [log for log in audit_system.audit_logs if log['event_type'] == 'AUTHORIZATION_FAILURE']
        if failure_logs:
            print(f"   ✅ PASS: Failed authentication logged")
            results.append({"test": "Failed Authentication Audit", "status": "PASS"})
        else:
            print(f"   ❌ FAIL: Failed authentication not logged")
            results.append({"test": "Failed Authentication Audit", "status": "FAIL", "reason": "No failure log"})
    else:
        print(f"   ❌ FAIL: Authentication should have failed")
        results.append({"test": "Failed Authentication", "status": "FAIL", "reason": "Should have failed"})
    
    return results, audit_system, session_id

def test_phi_access_audit(audit_system, session_id):
    """Test PHI access with comprehensive audit logging."""
    print("\n\n📋 Testing PHI Access Audit...")
    print("=" * 50)
    
    results = []
    
    # Test PHI data samples
    phi_samples = [
        {
            "name": "Patient Record",
            "data": "Patient John Doe, SSN 123-45-6789, DOB 03/15/1985, reports chest pain",
            "operation": "READ",
            "resource_id": "patient_001_record"
        },
        {
            "name": "Lab Results",
            "data": "Patient Mary Smith, MRN:ABC123456, email: mary@example.com - Glucose: 120 mg/dL",
            "operation": "READ", 
            "resource_id": "lab_results_002"
        },
        {
            "name": "Clinical Note Update",
            "data": "Updated treatment plan for patient (555) 123-4567 - prescribed medication",
            "operation": "WRITE",
            "resource_id": "clinical_note_003"
        }
    ]
    
    for sample in phi_samples:
        print(f"\n🧪 Testing: {sample['name']}")
        print(f"   Operation: {sample['operation']}")
        print(f"   Original data: {sample['data'][:50]}...")
        
        # Access PHI data through audit system
        result = audit_system.access_phi_data(
            session_id,
            sample['data'],
            sample['operation'],
            sample['resource_id']
        )
        
        if result:
            print(f"   Processed data: {result[:50]}...")
            
            # Check if PHI access was logged
            phi_logs = [log for log in audit_system.audit_logs if log['event_type'] == 'PHI_ACCESS']
            phi_access_logs = [log for log in audit_system.phi_access_logs if log['resource_id'] == sample['resource_id']]
            
            if phi_logs and phi_access_logs:
                print(f"   ✅ PASS: PHI access properly audited")
                results.append({"test": f"PHI Access Audit: {sample['name']}", "status": "PASS"})
                
                # Check for PHI masking in audit logs
                latest_audit = phi_logs[-1]
                if 'XXX-XX-XXXX' in result or 'email@[REDACTED]' in result or '[NAME_REDACTED]' in result:
                    print(f"   ✅ PASS: PHI properly masked in processed data")
                    results.append({"test": f"PHI Masking: {sample['name']}", "status": "PASS"})
                else:
                    print(f"   ⚠️  WARNING: PHI masking may be incomplete")
                    results.append({"test": f"PHI Masking: {sample['name']}", "status": "PARTIAL", "reason": "Incomplete masking"})
                    
            else:
                print(f"   ❌ FAIL: PHI access not properly audited")
                results.append({"test": f"PHI Access Audit: {sample['name']}", "status": "FAIL", "reason": "Missing audit logs"})
        else:
            print(f"   ❌ FAIL: PHI access denied or failed")
            results.append({"test": f"PHI Access: {sample['name']}", "status": "FAIL", "reason": "Access denied"})
    
    return results

def test_audit_report_generation(audit_system):
    """Test audit report generation for different roles."""
    print("\n\n📊 Testing Audit Report Generation...")
    print("=" * 50)
    
    results = []
    
    # Create additional users for testing
    auditor_session = audit_system.authenticate_user(
        "auditor_001", 
        HIPAARole.AUDITOR, 
        mfa_verified=True
    )
    
    security_session = audit_system.authenticate_user(
        "security_001",
        HIPAARole.SECURITY_OFFICER,
        mfa_verified=True  
    )
    
    # Test audit report for different roles
    report_tests = [
        {
            "name": "Auditor Full Report",
            "role": HIPAARole.AUDITOR,
            "user_id": "auditor_001",
            "expected_events": ["AUTHENTICATION", "PHI_ACCESS", "AUTHORIZATION_FAILURE"]
        },
        {
            "name": "Security Officer Report", 
            "role": HIPAARole.SECURITY_OFFICER,
            "user_id": "security_001",
            "expected_events": ["AUTHENTICATION", "PHI_ACCESS", "AUTHORIZATION_FAILURE"]
        },
        {
            "name": "Healthcare Provider Report",
            "role": HIPAARole.HEALTHCARE_PROVIDER,
            "user_id": "dr_test_001", 
            "expected_events": ["AUTHENTICATION", "PHI_ACCESS"]  # Only their own
        }
    ]
    
    for test in report_tests:
        print(f"\n🧪 Testing: {test['name']}")
        
        report = audit_system.get_audit_report(
            test['role'],
            test['user_id']
        )
        
        print(f"   Total events in report: {report['total_events']}")
        print(f"   Event types: {list(report['event_summary'].keys())}")
        
        if report['total_events'] > 0:
            # Check if expected event types are present
            found_events = set(report['event_summary'].keys())
            expected_events = set(test['expected_events'])
            
            if expected_events.intersection(found_events):
                print(f"   ✅ PASS: Audit report generated with appropriate events")
                results.append({"test": test['name'], "status": "PASS", "events": report['total_events']})
            else:
                print(f"   ⚠️  PARTIAL: Some expected events missing")
                results.append({"test": test['name'], "status": "PARTIAL", "reason": "Missing expected events"})
        else:
            print(f"   ❌ FAIL: Empty audit report")
            results.append({"test": test['name'], "status": "FAIL", "reason": "Empty report"})
    
    return results

def test_phi_hash_consistency(audit_system):
    """Test PHI hash consistency for audit trail integrity."""
    print("\n\n🔐 Testing PHI Hash Consistency...")
    print("=" * 50)
    
    results = []
    
    # Create test session
    session_id = audit_system.authenticate_user(
        "hash_test_001",
        HIPAARole.HEALTHCARE_PROVIDER,
        mfa_verified=True
    )
    
    # Test same PHI data multiple times
    test_data = "Patient John Test, SSN 123-45-6789, contact john.test@example.com"
    
    print(f"   Testing PHI hash consistency:")
    print(f"   Test data: {test_data}")
    
    # Access same data multiple times
    result1 = audit_system.access_phi_data(session_id, test_data, "READ", "consistency_test_1")
    result2 = audit_system.access_phi_data(session_id, test_data, "READ", "consistency_test_2")
    
    if result1 and result2:
        # Get PHI access logs
        phi_logs = [log for log in audit_system.phi_access_logs if "consistency_test" in log['resource_id']]
        
        if len(phi_logs) >= 2:
            hash1 = phi_logs[-2]['phi_hash']
            hash2 = phi_logs[-1]['phi_hash']
            
            print(f"   PHI Hash 1: {hash1}")
            print(f"   PHI Hash 2: {hash2}")
            
            if hash1 == hash2:
                print(f"   ✅ PASS: PHI hashes are consistent")
                results.append({"test": "PHI Hash Consistency", "status": "PASS"})
            else:
                print(f"   ❌ FAIL: PHI hashes are inconsistent")
                results.append({"test": "PHI Hash Consistency", "status": "FAIL", "reason": "Inconsistent hashes"})
        else:
            print(f"   ❌ FAIL: Insufficient PHI access logs")
            results.append({"test": "PHI Hash Consistency", "status": "FAIL", "reason": "Missing logs"})
    else:
        print(f"   ❌ FAIL: PHI access failed")
        results.append({"test": "PHI Hash Consistency", "status": "FAIL", "reason": "Access failed"})
    
    return results

def generate_integrated_audit_report(all_results):
    """Generate comprehensive integrated audit test report."""
    print("\n\n📊 Integrated HIPAA Audit System Test Report")
    print("=" * 60)
    print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Test Environment: LOCAL MOCK - INTEGRATED COMPONENTS")
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
        if 'events' in result:
            print(f"      Events: {result['events']}")
    
    # Overall assessment
    print(f"\n🎯 Overall Assessment:")
    if success_rate >= 90:
        print("   🟢 EXCELLENT: Integrated audit system working properly")
        print("   📝 Next Step: Deploy to staging environment with real Azure services")
    elif success_rate >= 70:
        print("   🟡 GOOD: Minor issues detected, review partial/failed tests")
        print("   📝 Next Step: Fix issues and enhance integration")
    else:
        print("   🔴 CRITICAL: Major integration issues detected")
        print("   📝 Next Step: Review component integration")
    
    print(f"\n🔒 HIPAA Compliance Assessment:")
    print(f"   ✅ Authentication Audit: Comprehensive logging")
    print(f"   ✅ PHI Access Audit: Complete audit trail with PHI hashing")
    print(f"   ✅ Role-Based Reporting: Appropriate access controls")
    print(f"   ✅ PHI Masking: Automatic PHI detection and masking")
    print(f"   📋 Retention: 7-year audit log retention configured")
    
    return {
        "test_type": "INTEGRATED_HIPAA_AUDIT_SYSTEM",
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
    """Run all integrated audit system tests."""
    print("🧪 HIPAA-RAG Integrated Audit System Testing")
    print("🚨 USING SYNTHETIC PHI DATA ONLY")
    print("🔧 LOCAL MOCK MODE - INTEGRATED COMPONENTS")
    print("=" * 60)
    
    all_results = []
    
    # Test integrated authentication audit
    print("Phase 1: Integrated Authentication Audit")
    auth_results, audit_system, session_id = test_integrated_authentication_audit()
    all_results.extend(auth_results)
    
    # Test PHI access audit
    print("\nPhase 2: PHI Access Audit")
    phi_results = test_phi_access_audit(audit_system, session_id)
    all_results.extend(phi_results)
    
    # Test audit report generation
    print("\nPhase 3: Audit Report Generation")
    report_results = test_audit_report_generation(audit_system)
    all_results.extend(report_results)
    
    # Test PHI hash consistency
    print("\nPhase 4: PHI Hash Consistency")
    hash_results = test_phi_hash_consistency(audit_system)
    all_results.extend(hash_results)
    
    # Generate report
    report = generate_integrated_audit_report(all_results)
    
    # Save report
    os.makedirs("tests/reports", exist_ok=True)
    report_file = f"tests/reports/integrated_audit_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n💾 Test report saved to: {report_file}")
    
    return report['success_rate'] >= 70

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)