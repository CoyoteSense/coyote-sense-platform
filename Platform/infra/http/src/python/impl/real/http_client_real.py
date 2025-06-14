"""
Real HTTP Client Implementation

This module provides a real HTTP client implementation using the requests library,
mirroring the C++ real implementation architecture.
"""

import time
import os
import sys
from typing import Dict, Optional
import requests
import urllib3

# Add the parent directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from interfaces.python.http_client import HttpClient, HttpRequest, HttpResponse, HttpMethod


class HttpClientReal(HttpClient):
    """Real HTTP client implementation using the requests library."""
    
    def __init__(self):
        """Initialize the real HTTP client."""
        self._default_timeout_ms = 10000
        self._default_headers = {}
        self._client_cert_path = ""
        self._client_key_path = ""
        self._ca_cert_path = ""
        self._verify_peer = True
        self._session = requests.Session()
        
        # Set up default headers
        self._session.headers.update({
            'User-Agent': 'CoyoteSense-HttpClient/1.0'
        })
    
    def execute(self, request: HttpRequest) -> HttpResponse:
        """Execute an HTTP request and return the response."""
        try:
            # Prepare request parameters
            method_map = {
                HttpMethod.GET: 'GET',
                HttpMethod.POST: 'POST',
                HttpMethod.PUT: 'PUT',
                HttpMethod.DELETE: 'DELETE',
                HttpMethod.PATCH: 'PATCH',
                HttpMethod.HEAD: 'HEAD',
                HttpMethod.OPTIONS: 'OPTIONS'
            }
            
            method = method_map.get(request.method, 'GET')
            timeout = request.timeout_ms / 1000.0  # Convert to seconds
            
            # Prepare headers
            headers = self._default_headers.copy()
            headers.update(request.headers)
            
            # Prepare SSL configuration
            verify = request.verify_peer
            cert = None
            
            if request.ca_cert_path:
                verify = request.ca_cert_path
            elif not request.verify_peer:
                verify = False
                
            if request.client_cert_path and request.client_key_path:
                cert = (request.client_cert_path, request.client_key_path)
            
            # Make the request
            response = self._session.request(
                method=method,
                url=request.url,
                data=request.body if request.body else None,
                headers=headers,
                timeout=timeout,
                verify=verify,
                cert=cert,
                allow_redirects=request.follow_redirects
            )
            
            # Convert response
            return HttpResponse(
                status_code=response.status_code,
                body=response.text,
                headers=dict(response.headers),
                error_message=""
            )
            
        except requests.exceptions.Timeout:
            return HttpResponse(
                status_code=408,
                body="",
                headers={},
                error_message="Request timeout"
            )
        except requests.exceptions.ConnectionError as e:
            return HttpResponse(
                status_code=0,
                body="",
                headers={},
                error_message=f"Connection error: {str(e)}"
            )
        except requests.exceptions.SSLError as e:
            return HttpResponse(
                status_code=0,
                body="",
                headers={},
                error_message=f"SSL error: {str(e)}"
            )
        except requests.exceptions.RequestException as e:
            return HttpResponse(
                status_code=0,
                body="",
                headers={},
                error_message=f"Request error: {str(e)}"
            )
        except Exception as e:
            return HttpResponse(
                status_code=0,
                body="",
                headers={},
                error_message=f"Unexpected error: {str(e)}"
            )
    
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
        self._session.headers.update(headers)
    
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
        if not verify:
            # Disable SSL warnings when verification is disabled
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def ping(self, url: str) -> bool:
        """Check connectivity to a URL."""
        try:
            response = self.get(url)
            return response.status_code < 500  # Consider any non-server error as successful ping
        except Exception:
            return False