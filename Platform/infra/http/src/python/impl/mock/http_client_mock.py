"""
Mock HTTP Client Implementation

This module provides a mock HTTP client implementation for testing,
mirroring the C++ mock implementation architecture with Python idioms.
"""

import json
import time
import random
import threading
import os
import sys
from collections import deque
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

# Add the parent directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from interfaces.python.http_client import HttpClient, HttpRequest, HttpResponse, HttpMethod


@dataclass
class RequestMatcher:
    """Matcher for setting up conditional mock responses."""
    url_pattern: str = ""
    method: Optional[HttpMethod] = None
    required_headers: Dict[str, str] = field(default_factory=dict)
    body_pattern: str = ""
    
    def matches(self, request: HttpRequest) -> bool:
        """Check if this matcher matches the given request."""
        if self.url_pattern and self.url_pattern not in request.url:
            return False
        
        if self.method and self.method != request.method:
            return False
        
        for key, value in self.required_headers.items():
            if key not in request.headers or request.headers[key] != value:
                return False
        
        if self.body_pattern and self.body_pattern not in request.body:
            return False
        
        return True


class HttpClientMock(HttpClient):
    """Mock HTTP client implementation for testing."""
    
    def __init__(self):
        """Initialize the mock HTTP client."""
        self._lock = threading.Lock()
        
        # Response queue for pre-configured responses
        self._response_queue = deque()
        
        # Default response when queue is empty
        self._default_response = HttpResponse(
            status_code=200,
            body="OK",
            headers={"Content-Type": "text/plain"},
            error_message=""
        )
        
        # Configuration
        self._default_timeout_ms = 10000
        self._default_headers = {}
        self._client_cert_path = ""
        self._client_key_path = ""
        self._ca_cert_path = ""
        self._verify_peer = True
        
        # Request recording
        self._recorded_requests = []
        self._record_requests = False
        
        # Error simulation
        self._simulate_network_error = False
        self._network_error_message = "Mock network error"
        self._simulated_latency_ms = 0
        self._failure_rate = 0.0
    
    def execute(self, request: HttpRequest) -> HttpResponse:
        """Execute an HTTP request and return the response."""
        with self._lock:
            # Record the request if recording is enabled
            if self._record_requests:
                self._recorded_requests.append(self._copy_request(request))
            
            # Simulate latency if configured
            if self._simulated_latency_ms > 0:
                time.sleep(self._simulated_latency_ms / 1000.0)
            
            # Simulate network error if configured
            if self._simulate_network_error:
                return HttpResponse(
                    status_code=0,
                    body="",
                    headers={},
                    error_message=self._network_error_message
                )
            
            # Simulate random failures if configured
            if self._failure_rate > 0 and random.random() < self._failure_rate:
                return HttpResponse(
                    status_code=500,
                    body="Simulated failure",
                    headers={},
                    error_message="Simulated random failure"
                )
            
            # Get response from queue or use default
            if self._response_queue:
                return self._response_queue.popleft()
            else:
                return self._default_response
    
    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        """Perform a GET request."""
        request = HttpRequest(
            url=url,
            method=HttpMethod.GET,
            headers=headers or {},
            timeout_ms=self._default_timeout_ms
        )
        return self.execute(request)
    
    def post(self, url: str, body: str = "", headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        """Perform a POST request."""
        request = HttpRequest(
            url=url,
            method=HttpMethod.POST,
            body=body,
            headers=headers or {},
            timeout_ms=self._default_timeout_ms
        )
        return self.execute(request)
    
    def put(self, url: str, body: str = "", headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        """Perform a PUT request."""
        request = HttpRequest(
            url=url,
            method=HttpMethod.PUT,
            body=body,
            headers=headers or {},
            timeout_ms=self._default_timeout_ms
        )
        return self.execute(request)
    
    def delete(self, url: str, headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        """Perform a DELETE request."""
        request = HttpRequest(
            url=url,
            method=HttpMethod.DELETE,
            headers=headers or {},
            timeout_ms=self._default_timeout_ms
        )
        return self.execute(request)
    
    def set_default_timeout(self, timeout_ms: int) -> None:
        """Set the default timeout for all requests."""
        self._default_timeout_ms = timeout_ms
    
    def set_default_headers(self, headers: Dict[str, str]) -> None:
        """Set default headers for all requests."""
        self._default_headers = headers.copy()
    
    def set_client_certificate(self, cert_path: str, key_path: str) -> None:
        """Set client certificate for SSL authentication."""
        self._client_cert_path = cert_path
        self._client_key_path = key_path
    
    def set_ca_certificate(self, ca_path: str) -> None:
        """Set CA certificate for SSL verification."""
        self._ca_cert_path = ca_path
    
    def set_verify_peer(self, verify: bool) -> None:
        """Enable or disable SSL peer verification."""
        self._verify_peer = verify
    
    def ping(self, url: str) -> bool:
        """Check connectivity to a URL."""
        # Mock ping always succeeds unless network error is simulated
        return not self._simulate_network_error
    
    # Mock-specific methods for testing
    
    def add_response(self, response: HttpResponse) -> None:
        """Add a response to the queue."""
        with self._lock:
            self._response_queue.append(response)
    
    def add_responses(self, responses: List[HttpResponse]) -> None:
        """Add multiple responses to the queue."""
        with self._lock:
            self._response_queue.extend(responses)
    
    def set_default_response(self, response: HttpResponse) -> None:
        """Set the default response for when queue is empty."""
        self._default_response = response
    
    def clear_responses(self) -> None:
        """Clear all queued responses."""
        with self._lock:
            self._response_queue.clear()
    
    def enable_request_recording(self, enable: bool = True) -> None:
        """Enable or disable request recording."""
        self._record_requests = enable
    
    def get_recorded_requests(self) -> List[HttpRequest]:
        """Get all recorded requests."""
        return self._recorded_requests.copy()
    
    def clear_recorded_requests(self) -> None:
        """Clear all recorded requests."""
        with self._lock:
            self._recorded_requests.clear()
    
    def simulate_network_error(self, simulate: bool = True, error_message: str = "Mock network error") -> None:
        """Simulate network errors."""
        self._simulate_network_error = simulate
        self._network_error_message = error_message
    
    def set_latency_simulation(self, latency_ms: int) -> None:
        """Set simulated latency for all requests."""
        self._simulated_latency_ms = latency_ms
    
    def set_failure_rate(self, rate: float) -> None:
        """Set random failure rate (0.0 to 1.0)."""
        self._failure_rate = max(0.0, min(1.0, rate))
    
    # Convenience methods for common responses
    
    def add_json_response(self, status_code: int, json_data: Any) -> None:
        """Add a JSON response to the queue."""
        response = HttpResponse(
            status_code=status_code,
            body=json.dumps(json_data),
            headers={"Content-Type": "application/json"},
            error_message=""
        )
        self.add_response(response)
    
    def add_success_response(self, body: str = "OK") -> None:
        """Add a successful response to the queue."""
        response = HttpResponse(
            status_code=200,
            body=body,
            headers={"Content-Type": "text/plain"},
            error_message=""
        )
        self.add_response(response)
    
    def add_error_response(self, status_code: int, error_body: str = "Error") -> None:
        """Add an error response to the queue."""
        response = HttpResponse(
            status_code=status_code,
            body=error_body,
            headers={"Content-Type": "text/plain"},
            error_message=""
        )
        self.add_response(response)
    
    def add_not_found_response(self) -> None:
        """Add a 404 Not Found response to the queue."""
        self.add_error_response(404, "Not Found")
    
    def add_server_error_response(self) -> None:
        """Add a 500 Internal Server Error response to the queue."""
        self.add_error_response(500, "Internal Server Error")
    
    def add_unauthorized_response(self) -> None:
        """Add a 401 Unauthorized response to the queue."""
        self.add_error_response(401, "Unauthorized")
    
    # State inspection methods
    
    def get_queued_response_count(self) -> int:
        """Get the number of queued responses."""
        return len(self._response_queue)
    
    def is_recording_requests(self) -> bool:
        """Check if request recording is enabled."""
        return self._record_requests
    
    def is_simulating_network_error(self) -> bool:
        """Check if network error simulation is enabled."""
        return self._simulate_network_error
    
    def _copy_request(self, request: HttpRequest) -> HttpRequest:
        """Create a copy of a request for recording."""
        return HttpRequest(
            url=request.url,
            method=request.method,
            body=request.body,
            headers=request.headers.copy(),
            timeout_ms=request.timeout_ms,
            client_cert_path=request.client_cert_path,
            client_key_path=request.client_key_path,
            ca_cert_path=request.ca_cert_path,
            verify_peer=request.verify_peer,
            follow_redirects=request.follow_redirects
        )