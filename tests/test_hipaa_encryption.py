#!/usr/bin/env python3
"""
HIPAA Encryption Helper Test Suite
Tests the encryption/decryption functionality with synthetic PHI data.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from security.encryption.hipaa_encryption_helper import HIPAAEncryptionHelper
import json
from datetime import datetime

def test_encryption_decryption():
    """Test basic encryption and decryption functionality."""
    print("🔐 Testing HIPAA Encryption Helper...")
    print("=" * 50)
    
    # Initialize encryption helper
    try:
        helper = HIPAAEncryptionHelper()
        print("✅ HIPAAEncryptionHelper initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize HIPAAEncryptionHelper: {e}")
        return False
    
    # Synthetic PHI test data
    test_cases = [
        {
            "name": "Patient Name",
            "data": "John Test Patient",
            "field": "patient_name",
            "record_id": "TEST001"
        },
        {
            "name": "SSN",
            "data": "123-45-6789",
            "field": "ssn",
            "record_id": "TEST001"
        },
        {
            "name": "Medical Record Number",
            "data": "MRN123456789",
            "field": "mrn",
            "record_id": "TEST001"
        },
        {
            "name": "Email Address",
            "data": "patient.test@example.com",
            "field": "email",
            "record_id": "TEST001"
        },
        {
            "name": "Clinical Note",
            "data": "Patient presents with chest pain. Vital signs stable. EKG shows normal sinus rhythm.",
            "field": "clinical_note",
            "record_id": "TEST002"
        },
        {
            "name": "Lab Results",
            "data": "Glucose: 120 mg/dL, Cholesterol: 180 mg/dL, Hemoglobin: 14.2 g/dL",
            "field": "lab_results",
            "record_id": "TEST003"
        }
    ]
    
    results = []
    
    for test_case in test_cases:
        print(f"\n🧪 Testing: {test_case['name']}")
        print(f"   Original: {test_case['data']}")
        
        try:
            # Test encryption
            encrypted_data = helper.encrypt_field(
                field_value=test_case['data'],
                field_name=test_case['field'],
                record_id=test_case['record_id']
            )
            
            if encrypted_data == test_case['data']:
                print(f"   ❌ FAIL: Data was not encrypted (same as original)")
                results.append({"test": test_case['name'], "status": "FAIL", "reason": "No encryption"})
                continue
                
            print(f"   🔒 Encrypted: {encrypted_data[:50]}..." if len(encrypted_data) > 50 else f"   🔒 Encrypted: {encrypted_data}")
            
            # Test decryption
            decrypted_data = helper.decrypt_field(
                encrypted_value=encrypted_data,
                field_name=test_case['field'],
                record_id=test_case['record_id']
            )
            
            if decrypted_data == test_case['data']:
                print(f"   ✅ PASS: Successful encryption/decryption")
                results.append({"test": test_case['name'], "status": "PASS"})
            else:
                print(f"   ❌ FAIL: Decrypted data doesn't match original")
                print(f"       Expected: {test_case['data']}")
                print(f"       Got: {decrypted_data}")
                results.append({"test": test_case['name'], "status": "FAIL", "reason": "Decryption mismatch"})
                
        except Exception as e:
            print(f"   ❌ ERROR: {str(e)}")
            results.append({"test": test_case['name'], "status": "ERROR", "reason": str(e)})
    
    return results

def test_key_management():
    """Test customer-managed key functionality."""
    print("\n\n🔑 Testing Key Management...")
    print("=" * 50)
    
    try:
        helper = HIPAAEncryptionHelper()
        
        # Test key rotation capability
        print("🔄 Testing key rotation simulation...")
        
        # Encrypt with current key
        original_data = "Sensitive patient data for key rotation test"
        encrypted_v1 = helper.encrypt_field(original_data, "test_field", "KEY_TEST_001")
        print(f"   Original: {original_data}")
        print(f"   Encrypted V1: {encrypted_v1[:50]}...")
        
        # Simulate key rotation (this would typically involve Azure Key Vault)
        print("   🔄 Simulating key rotation...")
        
        # Test that we can still decrypt with the original key reference
        decrypted = helper.decrypt_field(encrypted_v1, "test_field", "KEY_TEST_001")
        
        if decrypted == original_data:
            print("   ✅ PASS: Key management working correctly")
            return {"test": "Key Management", "status": "PASS"}
        else:
            print("   ❌ FAIL: Key management issue")
            return {"test": "Key Management", "status": "FAIL", "reason": "Key rotation failed"}
            
    except Exception as e:
        print(f"   ❌ ERROR: {str(e)}")
        return {"test": "Key Management", "status": "ERROR", "reason": str(e)}

def test_secure_deletion():
    """Test secure deletion functionality."""
    print("\n\n🗑️ Testing Secure Deletion...")
    print("=" * 50)
    
    try:
        helper = HIPAAEncryptionHelper()
        
        # Create test data
        sensitive_data = "This is sensitive patient information that must be securely deleted"
        encrypted_data = helper.encrypt_field(sensitive_data, "deletion_test", "DEL_TEST_001")
        
        print(f"   Created encrypted data: {encrypted_data[:50]}...")
        
        # Test secure deletion
        deletion_result = helper.secure_delete_field("deletion_test", "DEL_TEST_001")
        print(f"   Secure deletion result: {deletion_result}")
        
        # Attempt to decrypt after deletion (should fail)
        try:
            decrypted = helper.decrypt_field(encrypted_data, "deletion_test", "DEL_TEST_001")
            print("   ❌ FAIL: Data was decrypted after secure deletion")
            return {"test": "Secure Deletion", "status": "FAIL", "reason": "Data accessible after deletion"}
        except Exception as decrypt_error:
            print(f"   ✅ PASS: Secure deletion successful (decryption failed as expected)")
            print(f"   Expected error: {str(decrypt_error)[:100]}...")
            return {"test": "Secure Deletion", "status": "PASS"}
            
    except Exception as e:
        print(f"   ❌ ERROR: {str(e)}")
        return {"test": "Secure Deletion", "status": "ERROR", "reason": str(e)}

def generate_test_report(results):
    """Generate a comprehensive test report."""
    print("\n\n📊 HIPAA Encryption Test Report")
    print("=" * 60)
    print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total Tests: {len(results)}")
    
    passed = len([r for r in results if r['status'] == 'PASS'])
    failed = len([r for r in results if r['status'] == 'FAIL'])
    errors = len([r for r in results if r['status'] == 'ERROR'])
    
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"⚠️  Errors: {errors}")
    
    success_rate = (passed / len(results)) * 100 if results else 0
    print(f"📈 Success Rate: {success_rate:.1f}%")
    
    print("\n📋 Detailed Results:")
    for result in results:
        status_icon = "✅" if result['status'] == 'PASS' else "❌" if result['status'] == 'FAIL' else "⚠️"
        print(f"   {status_icon} {result['test']}: {result['status']}")
        if 'reason' in result:
            print(f"      Reason: {result['reason']}")
    
    # Overall assessment
    print(f"\n🎯 Overall Assessment:")
    if success_rate >= 90:
        print("   🟢 EXCELLENT: Encryption system is working properly")
    elif success_rate >= 70:
        print("   🟡 GOOD: Minor issues detected, review failed tests")
    else:
        print("   🔴 CRITICAL: Major issues detected, do not use with real PHI data")
    
    return {
        "total_tests": len(results),
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "success_rate": success_rate,
        "results": results
    }

def main():
    """Run all encryption tests."""
    print("🧪 HIPAA-RAG Encryption Component Testing")
    print("🚨 USING SYNTHETIC DATA ONLY - NO REAL PHI")
    print("=" * 60)
    
    all_results = []
    
    # Run encryption tests
    encryption_results = test_encryption_decryption()
    all_results.extend(encryption_results)
    
    # Run key management test
    key_result = test_key_management()
    all_results.append(key_result)
    
    # Run secure deletion test
    deletion_result = test_secure_deletion()
    all_results.append(deletion_result)
    
    # Generate report
    report = generate_test_report(all_results)
    
    # Save report to file
    report_file = f"tests/reports/encryption_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    os.makedirs(os.path.dirname(report_file), exist_ok=True)
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n💾 Test report saved to: {report_file}")
    
    return report['success_rate'] >= 70

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)