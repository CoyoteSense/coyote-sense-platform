#!/usr/bin/env python3
"""
Quick Test Runner for C++ OAuth2 Integration Tests
This script provides a simple way to test the OAuth2 server connectivity
and run basic integration tests without requiring full C++ build setup.
"""

import os
import sys
import json
import time
import subprocess
import requests
from urllib.parse import urlencode

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    END = '\033[0m'

def print_success(msg):
    print(f"{Colors.GREEN}[SUCCESS] {msg}{Colors.END}")

def print_error(msg):
    print(f"{Colors.RED}[ERROR] {msg}{Colors.END}")

def print_info(msg):
    print(f"{Colors.BLUE}[INFO] {msg}{Colors.END}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[WARNING] {msg}{Colors.END}")

def print_banner():
    print(f"{Colors.BLUE}========================================={Colors.END}")
    print(f"{Colors.BLUE}  C++ OAuth2 Integration Test Validator{Colors.END}")
    print(f"{Colors.BLUE}========================================={Colors.END}")

class OAuth2TestRunner:
    def __init__(self):
        self.server_url = os.getenv("OAUTH2_SERVER_URL", "http://localhost:8081")
        self.client_id = os.getenv("OAUTH2_CLIENT_ID", "test-client-id")
        self.client_secret = os.getenv("OAUTH2_CLIENT_SECRET", "test-client-secret")
        self.scope = os.getenv("OAUTH2_SCOPE", "api.read api.write")
        self.timeout = 10
        
    def test_server_connectivity(self):
        """Test if OAuth2 server is reachable"""
        print_info("Testing OAuth2 server connectivity...")
        
        try:
            response = requests.get(f"{self.server_url}/.well-known/oauth2", timeout=self.timeout)
            if response.status_code == 200:
                print_success("OAuth2 server is reachable")
                config = response.json()
                print_info(f"Server issuer: {config.get('issuer', 'N/A')}")
                print_info(f"Token endpoint: {config.get('token_endpoint', 'N/A')}")
                return True
            else:
                print_error(f"Server returned status {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print_error(f"Failed to connect to server: {e}")
            return False
    
    def test_client_credentials_flow(self):
        """Test client credentials grant flow"""
        print_info("Testing client credentials flow...")
        
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': self.scope
        }
        
        try:
            response = requests.post(
                f"{self.server_url}/token",
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                token_data = response.json()
                print_success("Client credentials flow successful")
                print_info(f"Token type: {token_data.get('token_type', 'N/A')}")
                print_info(f"Expires in: {token_data.get('expires_in', 'N/A')} seconds")
                print_info(f"Access token length: {len(token_data.get('access_token', ''))}")
                return token_data.get('access_token')
            else:
                print_error(f"Token request failed with status {response.status_code}")
                print_error(f"Response: {response.text}")
                return None
        except requests.exceptions.RequestException as e:
            print_error(f"Token request failed: {e}")
            return None
    
    def test_token_introspection(self, access_token):
        """Test token introspection endpoint"""
        print_info("Testing token introspection...")
        
        data = {
            'token': access_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        try:
            response = requests.post(
                f"{self.server_url}/introspect",
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                introspect_data = response.json()
                if introspect_data.get('active', False):
                    print_success("Token introspection successful - token is active")
                    return True
                else:
                    print_error("Token introspection failed - token is not active")
                    return False
            else:
                print_error(f"Introspection failed with status {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print_error(f"Introspection request failed: {e}")
            return False
    
    def test_invalid_credentials(self):
        """Test that invalid credentials are properly rejected"""
        print_info("Testing invalid credentials handling...")
        
        data = {
            'grant_type': 'client_credentials',
            'client_id': 'invalid-client',
            'client_secret': 'invalid-secret',
            'scope': self.scope
        }
        
        try:
            response = requests.post(
                f"{self.server_url}/token",
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=self.timeout
            )
            
            if response.status_code == 401:
                print_success("Invalid credentials properly rejected")
                return True
            else:
                print_error(f"Expected 401, got {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print_error(f"Invalid credentials test failed: {e}")
            return False
    
    def run_performance_test(self, num_requests=10):
        """Run a simple performance test"""
        print_info(f"Running performance test with {num_requests} requests...")
        
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': self.scope
        }
        
        start_time = time.time()
        successful_requests = 0
        
        for i in range(num_requests):
            try:
                response = requests.post(
                    f"{self.server_url}/token",
                    data=data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    successful_requests += 1
                    
            except requests.exceptions.RequestException:
                pass
        
        end_time = time.time()
        duration = end_time - start_time
        
        print_info(f"Performance test completed in {duration:.2f} seconds")
        print_info(f"Successful requests: {successful_requests}/{num_requests}")
        print_info(f"Average response time: {(duration/num_requests)*1000:.2f}ms")
        
        return successful_requests == num_requests
    
    def run_all_tests(self):
        """Run all integration tests"""
        print_banner()
        
        tests_passed = 0
        total_tests = 5
        
        # Test 1: Server connectivity
        if self.test_server_connectivity():
            tests_passed += 1
        
        # Test 2: Client credentials flow
        access_token = self.test_client_credentials_flow()
        if access_token:
            tests_passed += 1
        
        # Test 3: Token introspection (only if we have a token)
        if access_token and self.test_token_introspection(access_token):
            tests_passed += 1
        
        # Test 4: Invalid credentials
        if self.test_invalid_credentials():
            tests_passed += 1
        
        # Test 5: Performance test
        if self.run_performance_test(5):
            tests_passed += 1
        
        print()
        if tests_passed == total_tests:
            print_success(f"All {total_tests} tests passed!")
            return True
        else:
            print_error(f"{tests_passed}/{total_tests} tests passed")
            return False

def main():
    """Main function"""
    runner = OAuth2TestRunner()
    
    if runner.run_all_tests():
        print_success("C++ OAuth2 integration test environment is ready!")
        return 0
    else:
        print_error("Some tests failed. Please check the OAuth2 server setup.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
