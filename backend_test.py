#!/usr/bin/env python3

import requests
import sys
import json
import time
from datetime import datetime

class AntiPhishingAPITester:
    def __init__(self, base_url="https://nlp-fishguard.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED")
        else:
            print(f"❌ {name} - FAILED: {details}")
        
        self.test_results.append({
            'name': name,
            'success': success,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })

    def test_api_endpoint(self, name, method, endpoint, expected_status, data=None, timeout=30):
        """Test a single API endpoint"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=timeout)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=timeout)

            print(f"   Status Code: {response.status_code}")
            
            success = response.status_code == expected_status
            
            if success:
                try:
                    response_data = response.json()
                    print(f"   Response: {json.dumps(response_data, indent=2)[:200]}...")
                    self.log_test(name, True)
                    return True, response_data
                except:
                    print(f"   Response: {response.text[:200]}...")
                    self.log_test(name, True)
                    return True, {}
            else:
                error_details = f"Expected {expected_status}, got {response.status_code}"
                try:
                    error_data = response.json()
                    error_details += f" - {error_data}"
                except:
                    error_details += f" - {response.text[:200]}"
                
                self.log_test(name, False, error_details)
                return False, {}

        except requests.exceptions.Timeout:
            self.log_test(name, False, f"Request timeout after {timeout}s")
            return False, {}
        except Exception as e:
            self.log_test(name, False, f"Request error: {str(e)}")
            return False, {}

    def test_url_analysis(self, test_url, expected_risk_level=None):
        """Test URL analysis endpoint with specific URL"""
        print(f"\n🔍 Testing URL Analysis for: {test_url}")
        
        data = {
            "url": test_url,
            "user_id": "test_user"
        }
        
        success, response = self.test_api_endpoint(
            f"URL Analysis - {test_url[:50]}",
            "POST",
            "analyze",
            200,
            data,
            timeout=60  # Longer timeout for analysis
        )
        
        if success and response:
            # Validate response structure
            required_fields = ['id', 'url', 'is_phishing', 'confidence_score', 'risk_level', 
                             'analysis_details', 'features_extracted', 'ml_prediction', 
                             'nlp_analysis', 'processing_time']
            
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                self.log_test(f"Response Structure - {test_url[:30]}", False, 
                            f"Missing fields: {missing_fields}")
                return False, response
            
            # Validate data types and ranges
            if not isinstance(response['confidence_score'], (int, float)) or not (0 <= response['confidence_score'] <= 1):
                self.log_test(f"Confidence Score Validation - {test_url[:30]}", False, 
                            f"Invalid confidence score: {response['confidence_score']}")
                return False, response
            
            if response['risk_level'] not in ['low', 'medium', 'high', 'critical']:
                self.log_test(f"Risk Level Validation - {test_url[:30]}", False, 
                            f"Invalid risk level: {response['risk_level']}")
                return False, response
            
            self.log_test(f"Response Structure - {test_url[:30]}", True)
            
            # Check expected risk level if provided
            if expected_risk_level and response['risk_level'] != expected_risk_level:
                self.log_test(f"Expected Risk Level - {test_url[:30]}", False, 
                            f"Expected {expected_risk_level}, got {response['risk_level']}")
            
            print(f"   Analysis Result:")
            print(f"   - Is Phishing: {response['is_phishing']}")
            print(f"   - Confidence: {response['confidence_score']:.2%}")
            print(f"   - Risk Level: {response['risk_level']}")
            print(f"   - Processing Time: {response['processing_time']:.2f}s")
            
            return True, response
        
        return False, {}

    def run_comprehensive_tests(self):
        """Run all comprehensive tests"""
        print("🚀 Starting Anti-Phishing API Comprehensive Tests")
        print("=" * 60)
        
        # Test 1: Basic API Health Check
        print("\n📋 PHASE 1: Basic API Health Checks")
        
        # Test stats endpoint (should work even with empty database)
        self.test_api_endpoint("Statistics Endpoint", "GET", "stats", 200)
        
        # Test results endpoint (should work even with empty database)
        self.test_api_endpoint("Results Endpoint", "GET", "results", 200)
        
        # Test alerts endpoint (should work even with empty database)
        self.test_api_endpoint("Alerts Endpoint", "GET", "alerts", 200)
        
        # Test 2: URL Analysis Tests
        print("\n📋 PHASE 2: URL Analysis Tests")
        
        # Test legitimate URLs
        legitimate_urls = [
            "https://google.com",
            "https://github.com",
            "https://stackoverflow.com"
        ]
        
        for url in legitimate_urls:
            success, result = self.test_url_analysis(url)
            if success:
                time.sleep(2)  # Brief pause between requests
        
        # Test suspicious URLs (URLs with suspicious patterns)
        suspicious_urls = [
            "http://bit.ly/suspicious-link",
            "https://192.168.1.1/login",
            "https://paypal-security-update.com"
        ]
        
        for url in suspicious_urls:
            success, result = self.test_url_analysis(url)
            if success:
                time.sleep(2)  # Brief pause between requests
        
        # Test invalid URLs
        print("\n📋 PHASE 3: Invalid URL Tests")
        invalid_urls = [
            "not-a-url",
            "ftp://invalid-protocol.com",
            ""
        ]
        
        for url in invalid_urls:
            # These should either return 422 (validation error) or 500 (server error)
            data = {"url": url, "user_id": "test_user"}
            success, response = self.test_api_endpoint(
                f"Invalid URL - {url if url else 'empty'}",
                "POST",
                "analyze",
                422,  # Expecting validation error
                data
            )
            if not success:
                # Try with 500 status code as alternative
                success, response = self.test_api_endpoint(
                    f"Invalid URL (500) - {url if url else 'empty'}",
                    "POST",
                    "analyze",
                    500,
                    data
                )
        
        # Test 3: Data Persistence Tests
        print("\n📋 PHASE 4: Data Persistence Tests")
        
        # Analyze a URL and then check if it appears in results
        test_url = "https://example.com"
        success, analysis_result = self.test_url_analysis(test_url)
        
        if success:
            time.sleep(3)  # Wait for database write
            
            # Check if result appears in results endpoint
            success, results_data = self.test_api_endpoint("Results After Analysis", "GET", "results?limit=5", 200)
            
            if success and results_data:
                found_result = any(result.get('url') == test_url for result in results_data)
                self.log_test("Data Persistence Check", found_result, 
                            "Analysis result not found in results endpoint" if not found_result else "")
            
            # Check if high-risk URLs generate alerts
            if analysis_result.get('risk_level') in ['high', 'critical']:
                success, alerts_data = self.test_api_endpoint("Alerts After High-Risk Analysis", "GET", "alerts?limit=5", 200)
                
                if success and alerts_data:
                    found_alert = any(alert.get('url') == test_url for alert in alerts_data)
                    self.log_test("Alert Generation Check", found_alert,
                                "High-risk URL did not generate alert" if not found_alert else "")
        
        # Test 4: Statistics Validation
        print("\n📋 PHASE 5: Statistics Validation")
        
        success, stats_data = self.test_api_endpoint("Final Statistics Check", "GET", "stats", 200)
        
        if success and stats_data:
            # Validate statistics structure
            required_stats = ['total_analyses', 'phishing_detected', 'detection_rate', 'risk_distribution']
            missing_stats = [stat for stat in required_stats if stat not in stats_data]
            
            if missing_stats:
                self.log_test("Statistics Structure", False, f"Missing stats: {missing_stats}")
            else:
                self.log_test("Statistics Structure", True)
                
                # Validate data types
                if isinstance(stats_data.get('total_analyses'), int) and stats_data['total_analyses'] >= 0:
                    self.log_test("Statistics Data Types", True)
                else:
                    self.log_test("Statistics Data Types", False, "Invalid total_analyses value")

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        print(f"Total Tests Run: {self.tests_run}")
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Tests Failed: {self.tests_run - self.tests_passed}")
        print(f"Success Rate: {(self.tests_passed / self.tests_run * 100):.1f}%" if self.tests_run > 0 else "0%")
        
        # Show failed tests
        failed_tests = [test for test in self.test_results if not test['success']]
        if failed_tests:
            print(f"\n❌ FAILED TESTS ({len(failed_tests)}):")
            for test in failed_tests:
                print(f"   - {test['name']}: {test['details']}")
        
        print("\n" + "=" * 60)
        
        return self.tests_passed == self.tests_run

def main():
    """Main test execution"""
    tester = AntiPhishingAPITester()
    
    try:
        tester.run_comprehensive_tests()
        success = tester.print_summary()
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        tester.print_summary()
        return 1
    except Exception as e:
        print(f"\n\n💥 Unexpected error during testing: {str(e)}")
        tester.print_summary()
        return 1

if __name__ == "__main__":
    sys.exit(main())