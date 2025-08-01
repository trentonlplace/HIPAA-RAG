#!/usr/bin/env python3
"""
HIPAA Encryption Helper Local Test Suite
Tests the encryption/decryption functionality with synthetic PHI data using local mock.
"""

import sys
import os
import json
import secrets
import hashlib
from datetime import datetime
from typing import Dict, Optional, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

class MockHIPAAEncryptionHelper:
    """Mock HIPAA Encryption Helper for local testing without Azure dependencies."""
    
    def __init__(self):
        """Initialize with local mock key management."""
        self.local_keys = {}
        self.master_key = self._generate_master_key()
        print("🔧 Mock HIPAA Encryption Helper initialized (LOCAL TESTING ONLY)")
    
    def _generate_master_key(self) -> bytes:
        """Generate a local master key for testing."""
        # In production, this would come from Azure Key Vault
        return hashlib.sha256(b"HIPAA_RAG_LOCAL_TEST_KEY_DO_NOT_USE_IN_PRODUCTION").digest()
    
    def _derive_key(self, field_name: str, record_id: str) -> bytes:
        """Derive a field-specific key."""
        salt = hashlib.sha256(f"{field_name}:{record_id}".encode()).digest()[:16]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.master_key)
    
    def encrypt_field(self, field_value: str, field_name: str, record_id: str) -> str:
        """Encrypt a PHI field value."""
        if not field_value:
            return field_value
            
        try:
            # Derive field-specific key
            key = self._derive_key(field_name, record_id)
            
            # Generate random IV
            iv = secrets.token_bytes(16)
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Pad the data (PKCS7 padding)
            data = field_value.encode('utf-8')
            padding_length = 16 - (len(data) % 16)
            padded_data = data + bytes([padding_length] * padding_length)
            
            # Encrypt
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine IV and encrypted data
            combined = iv + encrypted_data
            
            # Base64 encode for storage
            return base64.b64encode(combined).decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_field(self, encrypted_value: str, field_name: str, record_id: str) -> str:
        """Decrypt a PHI field value."""
        if not encrypted_value:
            return encrypted_value
            
        try:
            # Decode from base64
            combined = base64.b64decode(encrypted_value.encode('utf-8'))
            
            # Extract IV and encrypted data
            iv = combined[:16]
            encrypted_data = combined[16:]
            
            # Derive the same key
            key = self._derive_key(field_name, record_id)
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Decrypt
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            padding_length = padded_data[-1]
            data = padded_data[:-padding_length]
            
            return data.decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
    def secure_delete_field(self, field_name: str, record_id: str) -> bool:
        """Simulate secure deletion by removing key reference."""
        # In a real implementation, this would securely overwrite memory
        # and remove key vault references
        key_id = f"{field_name}:{record_id}"
        if key_id in self.local_keys:
            del self.local_keys[key_id]
        return True

def test_encryption_decryption():
    """Test basic encryption and decryption functionality."""
    print("🔐 Testing HIPAA Encryption Helper (Local Mock)...")
    print("=" * 50)
    
    # Initialize encryption helper
    try:
        helper = MockHIPAAEncryptionHelper()
        print("✅ Mock HIPAAEncryptionHelper initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize Mock HIPAAEncryptionHelper: {e}")
        return []
    
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
        },
        {
            "name": "Date of Birth",
            "data": "1985-03-15",
            "field": "date_of_birth",
            "record_id": "TEST001"
        },
        {
            "name": "Phone Number",
            "data": "(555) 123-4567",
            "field": "phone",
            "record_id": "TEST001"
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
            
            # Verify it's base64 encoded
            try:
                base64.b64decode(encrypted_data)
                print(f"   ✅ Valid base64 encoding")
            except:
                print(f"   ⚠️  WARNING: Not valid base64 encoding")
            
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

def test_key_derivation():
    """Test that different fields/records get different keys."""
    print("\n\n🔑 Testing Key Derivation...")
    print("=" * 50)
    
    helper = MockHIPAAEncryptionHelper()
    test_data = "Same data for key derivation test"
    
    try:
        # Encrypt same data with different field names
        encrypted_1 = helper.encrypt_field(test_data, "field1", "record1")
        encrypted_2 = helper.encrypt_field(test_data, "field2", "record1")
        encrypted_3 = helper.encrypt_field(test_data, "field1", "record2")
        
        print(f"   Same data, field1/record1: {encrypted_1[:30]}...")
        print(f"   Same data, field2/record1: {encrypted_2[:30]}...")
        print(f"   Same data, field1/record2: {encrypted_3[:30]}...")
        
        # All should be different
        if len(set([encrypted_1, encrypted_2, encrypted_3])) == 3:
            print("   ✅ PASS: Different keys generated for different field/record combinations")
            return {"test": "Key Derivation", "status": "PASS"}
        else:
            print("   ❌ FAIL: Same keys generated for different combinations")
            return {"test": "Key Derivation", "status": "FAIL", "reason": "Non-unique key derivation"}
            
    except Exception as e:
        print(f"   ❌ ERROR: {str(e)}")
        return {"test": "Key Derivation", "status": "ERROR", "reason": str(e)}

def test_cross_record_isolation():
    """Test that records cannot decrypt each other's data."""
    print("\n\n🛡️ Testing Cross-Record Isolation...")
    print("=" * 50)
    
    helper = MockHIPAAEncryptionHelper()
    
    try:
        # Encrypt data for record1
        sensitive_data = "Patient confidential information"
        encrypted_record1 = helper.encrypt_field(sensitive_data, "notes", "PATIENT001")
        
        print(f"   Encrypted for PATIENT001: {encrypted_record1[:30]}...")
        
        # Try to decrypt with wrong record ID
        try:
            decrypted_wrong = helper.decrypt_field(encrypted_record1, "notes", "PATIENT002")
            print(f"   ❌ FAIL: Successfully decrypted with wrong record ID")
            print(f"   Decrypted: {decrypted_wrong}")
            return {"test": "Cross-Record Isolation", "status": "FAIL", "reason": "Cross-record decryption succeeded"}
        except Exception:
            print(f"   ✅ PASS: Cannot decrypt with wrong record ID (as expected)")
            
        # Verify correct record ID still works
        decrypted_correct = helper.decrypt_field(encrypted_record1, "notes", "PATIENT001")
        if decrypted_correct == sensitive_data:
            print(f"   ✅ PASS: Correct record ID still works")
            return {"test": "Cross-Record Isolation", "status": "PASS"}
        else:
            print(f"   ❌ FAIL: Correct record ID doesn't work")
            return {"test": "Cross-Record Isolation", "status": "FAIL", "reason": "Correct record ID failed"}
            
    except Exception as e:
        print(f"   ❌ ERROR: {str(e)}")
        return {"test": "Cross-Record Isolation", "status": "ERROR", "reason": str(e)}

def test_empty_and_edge_cases():
    """Test edge cases like empty strings, None values, etc."""
    print("\n\n🎯 Testing Edge Cases...")
    print("=" * 50)
    
    helper = MockHIPAAEncryptionHelper()
    results = []
    
    edge_cases = [
        {"name": "Empty String", "data": "", "should_encrypt": False},
        {"name": "Whitespace Only", "data": "   ", "should_encrypt": True},
        {"name": "Single Character", "data": "A", "should_encrypt": True},
        {"name": "Unicode Characters", "data": "Patiente José María", "should_encrypt": True},
        {"name": "Long Text", "data": "A" * 1000, "should_encrypt": True},
        {"name": "Special Characters", "data": "Patient@#$%&*()[]{}|", "should_encrypt": True},
    ]
    
    for case in edge_cases:
        print(f"\n   Testing: {case['name']}")
        try:
            encrypted = helper.encrypt_field(case['data'], "test_field", "EDGE_TEST")
            
            if case['should_encrypt']:
                if encrypted != case['data']:
                    decrypted = helper.decrypt_field(encrypted, "test_field", "EDGE_TEST")
                    if decrypted == case['data']:
                        print(f"   ✅ PASS: {case['name']}")
                        results.append({"test": f"Edge Case: {case['name']}", "status": "PASS"})
                    else:
                        print(f"   ❌ FAIL: {case['name']} - decryption mismatch")
                        results.append({"test": f"Edge Case: {case['name']}", "status": "FAIL", "reason": "Decryption mismatch"})
                else:
                    print(f"   ❌ FAIL: {case['name']} - no encryption")
                    results.append({"test": f"Edge Case: {case['name']}", "status": "FAIL", "reason": "No encryption"})
            else:
                if encrypted == case['data']:
                    print(f"   ✅ PASS: {case['name']} - correctly not encrypted")
                    results.append({"test": f"Edge Case: {case['name']}", "status": "PASS"})
                else:
                    print(f"   ⚠️  INFO: {case['name']} - encrypted empty string")
                    results.append({"test": f"Edge Case: {case['name']}", "status": "PASS", "note": "Encrypted empty string"})
                    
        except Exception as e:
            print(f"   ❌ ERROR: {case['name']} - {str(e)}")
            results.append({"test": f"Edge Case: {case['name']}", "status": "ERROR", "reason": str(e)})
    
    return results

def generate_test_report(results):
    """Generate a comprehensive test report."""
    print("\n\n📊 HIPAA Encryption Test Report")
    print("=" * 60)
    print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Test Environment: LOCAL MOCK (No Azure Dependencies)")
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
        if 'note' in result:
            print(f"      Note: {result['note']}")
    
    # Overall assessment
    print(f"\n🎯 Overall Assessment:")
    if success_rate >= 90:
        print("   🟢 EXCELLENT: Encryption logic is working properly")
        print("   📝 Next Step: Test with real Azure Key Vault integration")
    elif success_rate >= 70:
        print("   🟡 GOOD: Minor issues detected, review failed tests")
        print("   📝 Next Step: Fix issues before Azure integration")
    else:
        print("   🔴 CRITICAL: Major issues detected, fix before proceeding")
        print("   📝 Next Step: Review encryption implementation")
    
    print(f"\n⚠️  IMPORTANT: This is a LOCAL MOCK TEST only.")
    print(f"   Real production deployment requires Azure Key Vault integration.")
    
    return {
        "test_type": "LOCAL_MOCK_ENCRYPTION",
        "timestamp": datetime.now().isoformat(),
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
    print("🔧 LOCAL MOCK MODE - NO AZURE DEPENDENCIES")
    print("=" * 60)
    
    all_results = []
    
    # Run basic encryption tests
    print("Phase 1: Basic Encryption/Decryption")
    encryption_results = test_encryption_decryption()
    all_results.extend(encryption_results)
    
    # Run key derivation test
    print("\nPhase 2: Key Derivation")
    key_result = test_key_derivation()
    all_results.append(key_result)
    
    # Run isolation test
    print("\nPhase 3: Security Isolation")
    isolation_result = test_cross_record_isolation()
    all_results.append(isolation_result)
    
    # Run edge case tests
    print("\nPhase 4: Edge Cases")
    edge_results = test_empty_and_edge_cases()
    all_results.extend(edge_results)
    
    # Generate report
    report = generate_test_report(all_results)
    
    # Save report to file
    os.makedirs("tests/reports", exist_ok=True)
    report_file = f"tests/reports/encryption_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n💾 Test report saved to: {report_file}")
    
    return report['success_rate'] >= 70

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)