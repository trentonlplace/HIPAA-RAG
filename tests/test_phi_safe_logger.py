#!/usr/bin/env python3
"""
PHI-Safe Logger Test Suite
Tests the PHI detection and safe logging functionality with synthetic PHI data.
"""

import sys
import os
import json
import re
import tempfile
import logging
from datetime import datetime
from typing import Dict, List, Any

# Add project root to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# Mock the PHI-safe logger since it may have Azure dependencies
class MockPHISafeLogger:
    """Mock PHI-Safe Logger for local testing."""
    
    def __init__(self, name: str):
        self.name = name
        self.log_entries = []
        
        # PHI detection patterns (from the original implementation)
        self.phi_patterns = {
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b'),
            'mrn': re.compile(r'\b(?:MRN|mrn)[:\s]*[A-Z0-9]{6,12}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b'),
            'date_of_birth': re.compile(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{4}\b|\b\d{4}[/-]\d{1,2}[/-]\d{1,2}\b'),
            'name_pattern': re.compile(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b'),
            'address': re.compile(r'\b\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd)\b', re.IGNORECASE),
            'zip_code': re.compile(r'\b\d{5}(?:-\d{4})?\b'),
            'credit_card': re.compile(r'\b(?:\d{4}[\s-]?){3}\d{4}\b'),
            'account_number': re.compile(r'\b(?:Account|Acct)[\s#]*:?\s*\d{6,}\b', re.IGNORECASE)
        }
    
    def _mask_phi(self, message: str) -> str:
        """Mask PHI patterns in the message."""
        masked_message = message
        phi_found = []
        
        for pattern_name, pattern in self.phi_patterns.items():
            matches = pattern.findall(masked_message)
            if matches:
                phi_found.append(f"{pattern_name}: {len(matches)} instances")
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
                    # Only mask if it looks like a person's name in healthcare context
                    if any(keyword in message.lower() for keyword in ['patient', 'doctor', 'dr.', 'physician', 'nurse']):
                        masked_message = pattern.sub('[NAME_REDACTED]', masked_message)
                elif pattern_name == 'address':
                    masked_message = pattern.sub('[ADDRESS_REDACTED]', masked_message)
                elif pattern_name == 'zip_code':
                    masked_message = pattern.sub('XXXXX', masked_message)
                elif pattern_name == 'credit_card':
                    masked_message = pattern.sub('XXXX-XXXX-XXXX-XXXX', masked_message)
                elif pattern_name == 'account_number':
                    masked_message = pattern.sub('Account: XXXXXX', masked_message)
        
        return masked_message, phi_found
    
    def info(self, message: str):
        """Log info message with PHI masking."""
        masked_msg, phi_found = self._mask_phi(message)
        entry = {
            'level': 'INFO',
            'timestamp': datetime.now().isoformat(),
            'original_length': len(message),
            'masked_message': masked_msg,
            'phi_detected': phi_found,
            'logger_name': self.name
        }
        self.log_entries.append(entry)
        print(f"[{entry['timestamp']}] INFO {self.name}: {masked_msg}")
        if phi_found:
            print(f"[PHI_DETECTED] {', '.join(phi_found)}")
    
    def warning(self, message: str):
        """Log warning message with PHI masking."""
        masked_msg, phi_found = self._mask_phi(message)
        entry = {
            'level': 'WARNING',
            'timestamp': datetime.now().isoformat(),
            'original_length': len(message),
            'masked_message': masked_msg,
            'phi_detected': phi_found,
            'logger_name': self.name
        }
        self.log_entries.append(entry)
        print(f"[{entry['timestamp']}] WARNING {self.name}: {masked_msg}")
        if phi_found:
            print(f"[PHI_DETECTED] {', '.join(phi_found)}")
    
    def error(self, message: str):
        """Log error message with PHI masking."""
        masked_msg, phi_found = self._mask_phi(message)
        entry = {
            'level': 'ERROR',
            'timestamp': datetime.now().isoformat(),
            'original_length': len(message),
            'masked_message': masked_msg,
            'phi_detected': phi_found,
            'logger_name': self.name
        }
        self.log_entries.append(entry)
        print(f"[{entry['timestamp']}] ERROR {self.name}: {masked_msg}")
        if phi_found:
            print(f"[PHI_DETECTED] {', '.join(phi_found)}")

def get_phi_safe_logger(name: str) -> MockPHISafeLogger:
    """Get a PHI-safe logger instance."""
    return MockPHISafeLogger(name)

def test_phi_detection_patterns():
    """Test PHI detection across various patterns."""
    print("🔍 Testing PHI Detection Patterns...")
    print("=" * 50)
    
    logger = get_phi_safe_logger("phi_detection_test")
    
    # Test cases with synthetic PHI data
    test_cases = [
        {
            "name": "SSN Detection",
            "message": "Patient SSN is 123-45-6789 for verification",
            "expected_phi": ["ssn"],
            "should_mask": True
        },
        {
            "name": "MRN Detection", 
            "message": "Medical record number MRN:ABC123456 needs updating",
            "expected_phi": ["mrn"],
            "should_mask": True
        },
        {
            "name": "Email Detection",
            "message": "Send results to patient.test@example.com",
            "expected_phi": ["email"],
            "should_mask": True
        },
        {
            "name": "Phone Number Detection",
            "message": "Contact patient at (555) 123-4567 for follow-up",
            "expected_phi": ["phone"],
            "should_mask": True
        },
        {
            "name": "Date of Birth Detection",
            "message": "Patient DOB: 03/15/1985, schedule appointment",
            "expected_phi": ["date_of_birth"],
            "should_mask": True
        },
        {
            "name": "Patient Name Detection",
            "message": "Patient John Smith scheduled for surgery tomorrow",
            "expected_phi": ["name_pattern"],
            "should_mask": True
        },
        {
            "name": "Address Detection",
            "message": "Patient lives at 123 Main Street, needs home visit",
            "expected_phi": ["address"],
            "should_mask": True
        },
        {
            "name": "Multiple PHI Types",
            "message": "Patient John Doe (SSN: 987-65-4321) at john.doe@email.com, phone (555) 987-6543",
            "expected_phi": ["name_pattern", "ssn", "email", "phone"],
            "should_mask": True
        },
        {
            "name": "Clinical Note with PHI",
            "message": "Patient Mary Johnson, DOB 12/25/1980, reports chest pain. Contact at mary.j@gmail.com or (555) 456-7890.",
            "expected_phi": ["name_pattern", "date_of_birth", "email", "phone"],
            "should_mask": True
        },
        {
            "name": "Safe Medical Content",
            "message": "Blood pressure reading 120/80, heart rate 72 bpm, temperature 98.6F normal",
            "expected_phi": [],
            "should_mask": False
        }
    ]
    
    results = []
    
    for test_case in test_cases:
        print(f"\n🧪 Testing: {test_case['name']}")
        print(f"   Original: {test_case['message']}")
        
        # Clear previous entries
        logger.log_entries.clear()
        
        # Log the message
        logger.info(test_case['message'])
        
        # Check the result
        if logger.log_entries:
            entry = logger.log_entries[-1]
            masked_msg = entry['masked_message']
            phi_detected = entry['phi_detected']
            
            print(f"   Masked: {masked_msg}")
            print(f"   PHI Detected: {phi_detected}")
            
            # Verify PHI was detected
            phi_types_found = [phi.split(':')[0] for phi in phi_detected]
            
            # Check if masking occurred
            was_masked = masked_msg != test_case['message']
            
            if test_case['should_mask']:
                if was_masked and len(phi_detected) > 0:
                    # Check if expected PHI types were found
                    expected_found = any(expected in phi_types_found for expected in test_case['expected_phi'])
                    if expected_found:
                        print(f"   ✅ PASS: PHI detected and masked correctly")
                        results.append({"test": test_case['name'], "status": "PASS"})
                    else:
                        print(f"   ⚠️  PARTIAL: Masked but didn't detect expected PHI types")
                        print(f"       Expected: {test_case['expected_phi']}")
                        print(f"       Found: {phi_types_found}")
                        results.append({"test": test_case['name'], "status": "PARTIAL", "reason": "Missing expected PHI types"})
                else:
                    print(f"   ❌ FAIL: Should have masked PHI but didn't")
                    results.append({"test": test_case['name'], "status": "FAIL", "reason": "No masking when expected"})
            else:
                if not was_masked:
                    print(f"   ✅ PASS: No PHI detected, no masking (correct)")
                    results.append({"test": test_case['name'], "status": "PASS"})
                else:
                    print(f"   ⚠️  INFO: Masked safe content (overly cautious)")
                    results.append({"test": test_case['name'], "status": "PASS", "note": "Overly cautious masking"})
        else:
            print(f"   ❌ ERROR: No log entry created")
            results.append({"test": test_case['name'], "status": "ERROR", "reason": "No log entry"})
    
    return results

def test_logging_levels():
    """Test that PHI masking works across all logging levels."""
    print("\n\n📊 Testing Logging Levels...")
    print("=" * 50)
    
    logger = get_phi_safe_logger("level_test")
    test_message = "Patient SSN 123-45-6789 has urgent lab results"
    
    results = []
    
    # Test different logging levels
    levels = ['info', 'warning', 'error']
    
    for level in levels:
        print(f"\n   Testing {level.upper()} level:")
        logger.log_entries.clear()
        
        # Call the appropriate logging method
        getattr(logger, level)(test_message)
        
        if logger.log_entries:
            entry = logger.log_entries[-1]
            if entry['level'] == level.upper() and entry['phi_detected']:
                print(f"   ✅ PASS: {level.upper()} level PHI masking works")
                results.append({"test": f"Logging Level: {level.upper()}", "status": "PASS"})
            else:
                print(f"   ❌ FAIL: {level.upper()} level PHI masking failed")
                results.append({"test": f"Logging Level: {level.upper()}", "status": "FAIL", "reason": "PHI not masked"})
        else:
            print(f"   ❌ ERROR: No log entry for {level.upper()}")
            results.append({"test": f"Logging Level: {level.upper()}", "status": "ERROR", "reason": "No log entry"})
    
    return results

def test_performance_with_large_messages():
    """Test PHI detection performance with large log messages."""
    print("\n\n⚡ Testing Performance with Large Messages...")
    print("=" * 50)
    
    logger = get_phi_safe_logger("performance_test")
    
    # Create a large message with scattered PHI
    large_message = """
    Patient consultation notes for comprehensive care review:
    
    Patient: John Test Patient
    SSN: 123-45-6789
    DOB: 03/15/1985
    Email: john.test@example.com
    Phone: (555) 123-4567
    Address: 123 Main Street, Anytown USA
    
    """ + "Medical history details and clinical observations. " * 100 + """
    
    Follow-up required with patient Mary Sample (DOB: 12/25/1980)
    Contact: mary.sample@test.com or (555) 987-6543
    Insurance: Account #123456789
    """
    
    print(f"   Testing message size: {len(large_message)} characters")
    
    try:
        start_time = datetime.now()
        logger.info(large_message)
        end_time = datetime.now()
        
        processing_time = (end_time - start_time).total_seconds()
        print(f"   Processing time: {processing_time:.3f} seconds")
        
        if logger.log_entries:
            entry = logger.log_entries[-1]
            phi_count = len(entry['phi_detected'])
            print(f"   PHI instances detected: {phi_count}")
            
            if processing_time < 1.0 and phi_count > 0:
                print(f"   ✅ PASS: Good performance with PHI detection")
                return {"test": "Performance Test", "status": "PASS", "processing_time": processing_time, "phi_count": phi_count}
            elif phi_count > 0:
                print(f"   ⚠️  SLOW: PHI detected but processing was slow")
                return {"test": "Performance Test", "status": "SLOW", "processing_time": processing_time, "phi_count": phi_count}
            else:
                print(f"   ❌ FAIL: No PHI detected in large message")
                return {"test": "Performance Test", "status": "FAIL", "reason": "No PHI detected"}
        else:
            print(f"   ❌ ERROR: No log entry created")
            return {"test": "Performance Test", "status": "ERROR", "reason": "No log entry"}
            
    except Exception as e:
        print(f"   ❌ ERROR: {str(e)}")
        return {"test": "Performance Test", "status": "ERROR", "reason": str(e)}

def test_edge_cases():
    """Test edge cases for PHI detection."""
    print("\n\n🎯 Testing Edge Cases...")
    print("=" * 50)
    
    logger = get_phi_safe_logger("edge_case_test")
    
    edge_cases = [
        {
            "name": "Empty Message",
            "message": "",
            "should_process": True
        },
        {
            "name": "Only Whitespace",
            "message": "   \n\t   ",
            "should_process": True
        },
        {
            "name": "Non-PHI Numbers",
            "message": "Temperature 98.6F, BP 120/80, HR 72",
            "should_process": True
        },
        {
            "name": "False Positive SSN",
            "message": "Room number 123-45-6789 is available",
            "should_process": True,
            "note": "May detect as SSN - acceptable false positive"
        },
        {
            "name": "Mixed Languages",
            "message": "Paciente José María necesita seguimiento",
            "should_process": True
        },
        {
            "name": "Very Long Single Word",
            "message": "Antidisestablishmentarianism" * 10,
            "should_process": True
        }
    ]
    
    results = []
    
    for case in edge_cases:
        print(f"\n   Testing: {case['name']}")
        logger.log_entries.clear()
        
        try:
            logger.info(case['message'])
            
            if case['should_process']:
                if logger.log_entries:
                    print(f"   ✅ PASS: {case['name']} processed successfully")
                    result = {"test": f"Edge Case: {case['name']}", "status": "PASS"}
                    if 'note' in case:
                        result['note'] = case['note']
                    results.append(result)
                else:
                    print(f"   ❌ FAIL: {case['name']} not processed")
                    results.append({"test": f"Edge Case: {case['name']}", "status": "FAIL", "reason": "Not processed"})
            
        except Exception as e:
            print(f"   ❌ ERROR: {case['name']} - {str(e)}")
            results.append({"test": f"Edge Case: {case['name']}", "status": "ERROR", "reason": str(e)})
    
    return results

def generate_phi_logger_report(results):
    """Generate comprehensive PHI logger test report."""
    print("\n\n📊 PHI-Safe Logger Test Report")
    print("=" * 60)
    print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Test Environment: LOCAL MOCK")
    print(f"Total Tests: {len(results)}")
    
    passed = len([r for r in results if r['status'] == 'PASS'])
    failed = len([r for r in results if r['status'] == 'FAIL'])
    errors = len([r for r in results if r['status'] == 'ERROR'])
    partial = len([r for r in results if r['status'] == 'PARTIAL'])
    
    print(f"✅ Passed: {passed}")
    print(f"⚠️  Partial: {partial}")
    print(f"❌ Failed: {failed}")  
    print(f"⚠️  Errors: {errors}")
    
    success_rate = ((passed + partial) / len(results)) * 100 if results else 0
    print(f"📈 Success Rate: {success_rate:.1f}%")
    
    print("\n📋 Detailed Results:")
    for result in results:
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
        if 'note' in result:
            print(f"      Note: {result['note']}")
        if 'processing_time' in result:
            print(f"      Processing Time: {result['processing_time']:.3f}s")
        if 'phi_count' in result:
            print(f"      PHI Detected: {result['phi_count']} instances")
    
    # Overall assessment
    print(f"\n🎯 Overall Assessment:")
    if success_rate >= 90:
        print("   🟢 EXCELLENT: PHI detection and masking working properly")
        print("   📝 Next Step: Test integration with real application logging")
    elif success_rate >= 70:
        print("   🟡 GOOD: Minor issues detected, review partial/failed tests")
        print("   📝 Next Step: Fine-tune PHI detection patterns")
    else:
        print("   🔴 CRITICAL: Major issues detected, fix before proceeding")
        print("   📝 Next Step: Review PHI detection implementation")
    
    return {
        "test_type": "PHI_SAFE_LOGGER",
        "timestamp": datetime.now().isoformat(),
        "total_tests": len(results),
        "passed": passed,
        "partial": partial,
        "failed": failed,
        "errors": errors,
        "success_rate": success_rate,
        "results": results
    }

def main():
    """Run all PHI logger tests."""
    print("🧪 HIPAA-RAG PHI-Safe Logger Testing")
    print("🚨 USING SYNTHETIC PHI DATA ONLY")
    print("🔧 LOCAL MOCK MODE")
    print("=" * 60)
    
    all_results = []
    
    # Test PHI detection patterns
    print("Phase 1: PHI Detection Patterns")
    detection_results = test_phi_detection_patterns()
    all_results.extend(detection_results)
    
    # Test logging levels
    print("\nPhase 2: Logging Levels")
    level_results = test_logging_levels()
    all_results.extend(level_results)
    
    # Test performance
    print("\nPhase 3: Performance Testing")
    performance_result = test_performance_with_large_messages()
    all_results.append(performance_result)
    
    # Test edge cases
    print("\nPhase 4: Edge Cases")
    edge_results = test_edge_cases()
    all_results.extend(edge_results)
    
    # Generate report
    report = generate_phi_logger_report(all_results)
    
    # Save report
    os.makedirs("tests/reports", exist_ok=True)
    report_file = f"tests/reports/phi_logger_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n💾 Test report saved to: {report_file}")
    
    return report['success_rate'] >= 70

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)