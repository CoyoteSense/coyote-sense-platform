"""
Unit tests for Mock HTTP Client

This module contains unit tests for the mock HTTP client functionality,
mirroring the C++ test patterns but using pytest conventions.
"""

import json
import os
import sys
import pytest
from unittest.mock import patch

# Add the http directory to Python path for imports
http_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
sys.path.insert(0, http_root)

from modes.mock.python.http_client_mock import HttpClientMock
from interfaces.python.http_client import HttpRequest, HttpResponse, HttpMethod


class TestHttpClientMock:
    """Test cases for mock HTTP client."""
    
    def setup_method(self):
        """Set up before each test method."""
        self.client = HttpClientMock()
    
    def test_default_response(self):
        """Test that default response is returned when no responses are queued."""
        response = self.client.get("http://example.com")
        assert response.is_success
        assert response.status_code == 200
        assert response.body == "OK"
    
    def test_queued_responses(self):
        """Test that queued responses are returned in order."""
        # Add responses to queue
        self.client.add_success_response("First response")
        self.client.add_success_response("Second response")
        
        # First request should get first response
        response1 = self.client.get("http://example.com")
        assert response1.body == "First response"
        
        # Second request should get second response
        response2 = self.client.get("http://example.com")
        assert response2.body == "Second response"
        
        # Third request should get default response
        response3 = self.client.get("http://example.com")
        assert response3.body == "OK"
    
    def test_json_response(self):
        """Test adding JSON responses."""
        test_data = {"message": "Hello, World!", "status": "success"}
        self.client.add_json_response(200, test_data)
        
        response = self.client.get("http://example.com/api")
        assert response.status_code == 200
        assert response.get_header("Content-Type") == "application/json"
        
        parsed_data = json.loads(response.body)
        assert parsed_data == test_data
    
    def test_error_responses(self):
        """Test various error response types."""
        # Test custom error response
        self.client.add_error_response(400, "Bad Request")
        response = self.client.get("http://example.com")
        assert response.status_code == 400
        assert response.body == "Bad Request"
        assert not response.is_success
        
        # Test not found response
        self.client.add_not_found_response()
        response = self.client.get("http://example.com")
        assert response.status_code == 404
        assert response.body == "Not Found"
        
        # Test server error response
        self.client.add_server_error_response()
        response = self.client.get("http://example.com")
        assert response.status_code == 500
        assert response.body == "Internal Server Error"
        
        # Test unauthorized response
        self.client.add_unauthorized_response()
        response = self.client.get("http://example.com")
        assert response.status_code == 401
        assert response.body == "Unauthorized"
    
    def test_request_recording(self):
        """Test request recording functionality."""
        # Enable recording
        self.client.enable_request_recording(True)
        assert self.client.is_recording_requests()
        
        # Make some requests
        self.client.get("http://example.com/api/users")
        self.client.post("http://example.com/api/users", "{'name': 'John'}")
        self.client.put("http://example.com/api/users/1", "{'name': 'Jane'}")
        self.client.delete("http://example.com/api/users/1")
        
        # Check recorded requests
        recorded = self.client.get_recorded_requests()
        assert len(recorded) == 4
        
        assert recorded[0].method == HttpMethod.GET
        assert recorded[0].url == "http://example.com/api/users"
        
        assert recorded[1].method == HttpMethod.POST
        assert recorded[1].body == "{'name': 'John'}"
        
        assert recorded[2].method == HttpMethod.PUT
        assert recorded[2].body == "{'name': 'Jane'}"
        
        assert recorded[3].method == HttpMethod.DELETE
        
        # Test clearing recorded requests
        self.client.clear_recorded_requests()
        recorded = self.client.get_recorded_requests()
        assert len(recorded) == 0
    
    def test_network_error_simulation(self):
        """Test network error simulation."""
        # Enable network error simulation
        self.client.simulate_network_error(True, "Custom network error")
        assert self.client.is_simulating_network_error()
        
        response = self.client.get("http://example.com")
        assert response.status_code == 0
        assert response.error_message == "Custom network error"
        assert not response.is_success
        
        # Disable network error simulation
        self.client.simulate_network_error(False)
        assert not self.client.is_simulating_network_error()
        
        response = self.client.get("http://example.com")
        assert response.status_code == 200
        assert response.is_success
    
    def test_latency_simulation(self):
        """Test latency simulation."""
        import time
        
        # Set latency simulation
        self.client.set_latency_simulation(100)  # 100ms
        
        start_time = time.time()
        response = self.client.get("http://example.com")
        end_time = time.time()
        
        elapsed_ms = (end_time - start_time) * 1000
        assert elapsed_ms >= 100  # Should take at least 100ms
        assert response.is_success
    
    def test_failure_rate_simulation(self):
        """Test random failure simulation."""
        # Set 100% failure rate
        self.client.set_failure_rate(1.0)
        
        response = self.client.get("http://example.com")
        assert response.status_code == 500
        assert "failure" in response.body.lower()
        
        # Set 0% failure rate
        self.client.set_failure_rate(0.0)
        
        response = self.client.get("http://example.com")
        assert response.is_success
    
    def test_ping_functionality(self):
        """Test ping functionality."""
        # Normal ping should succeed
        assert self.client.ping("http://example.com")
        
        # Ping should fail when network error is simulated
        self.client.simulate_network_error(True)
        assert not self.client.ping("http://example.com")
    
    def test_http_methods(self):
        """Test all HTTP methods."""
        headers = {"Content-Type": "application/json"}
        body = '{"test": true}'
        
        # Test GET
        response = self.client.get("http://example.com", headers)
        assert response.is_success
        
        # Test POST
        response = self.client.post("http://example.com", body, headers)
        assert response.is_success
        
        # Test PUT
        response = self.client.put("http://example.com", body, headers)
        assert response.is_success
        
        # Test DELETE
        response = self.client.delete("http://example.com", headers)
        assert response.is_success
    
    def test_configuration_methods(self):
        """Test configuration methods."""
        # Test timeout setting
        self.client.set_default_timeout(5000)
        
        # Test headers setting
        headers = {"Authorization": "Bearer token123"}
        self.client.set_default_headers(headers)
        
        # Test SSL configuration
        self.client.set_client_certificate("/path/to/cert.pem", "/path/to/key.pem")
        self.client.set_ca_certificate("/path/to/ca.pem")
        self.client.set_verify_peer(False)
        
        # These should not raise exceptions
        response = self.client.get("http://example.com")
        assert response.is_success
    
    def test_multiple_responses(self):
        """Test adding multiple responses at once."""
        responses = [
            HttpResponse(200, "Response 1", {}),
            HttpResponse(201, "Response 2", {}),
            HttpResponse(202, "Response 3", {})
        ]
        
        self.client.add_responses(responses)
        assert self.client.get_queued_response_count() == 3
        
        # Use all responses
        response1 = self.client.get("http://example.com")
        assert response1.body == "Response 1"
        
        response2 = self.client.get("http://example.com")
        assert response2.body == "Response 2"
        
        response3 = self.client.get("http://example.com")
        assert response3.body == "Response 3"
        
        assert self.client.get_queued_response_count() == 0
    
    def test_clear_responses(self):
        """Test clearing queued responses."""
        self.client.add_success_response("Test")
        self.client.add_success_response("Test2")
        assert self.client.get_queued_response_count() == 2
        
        self.client.clear_responses()
        assert self.client.get_queued_response_count() == 0
    
    def test_set_default_response(self):
        """Test setting a custom default response."""
        custom_default = HttpResponse(
            status_code=418,
            body="I'm a teapot",
            headers={"Content-Type": "text/plain"}
        )
        
        self.client.set_default_response(custom_default)
        
        response = self.client.get("http://example.com")
        assert response.status_code == 418
        assert response.body == "I'm a teapot"
