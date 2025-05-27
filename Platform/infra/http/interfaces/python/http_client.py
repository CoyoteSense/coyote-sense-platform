"""
HTTP Client Interface Module

This module provides abstract base classes for HTTP client functionality,
mirroring the C++ interface architecture but using Python conventions.
"""

from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Dict, Optional, Any
import dataclasses


class HttpMethod(Enum):
    """HTTP method enumeration."""
    GET = auto()
    POST = auto()
    PUT = auto()
    DELETE = auto()
    PATCH = auto()
    HEAD = auto()
    OPTIONS = auto()


@dataclasses.dataclass
class HttpResponse:
    """HTTP response data container."""
    status_code: int
    body: str
    headers: Dict[str, str]
    error_message: str = ""
    
    @property
    def is_success(self) -> bool:
        """Check if the response indicates success (2xx status code)."""
        return 200 <= self.status_code < 300
    
    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Get a header value by name (case-insensitive)."""
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default


@dataclasses.dataclass
class HttpRequest:
    """HTTP request data container."""
    url: str = ""
    method: HttpMethod = HttpMethod.GET
    body: str = ""
    headers: Dict[str, str] = dataclasses.field(default_factory=dict)
    timeout_ms: int = 10000
    client_cert_path: str = ""
    client_key_path: str = ""
    ca_cert_path: str = ""
    verify_peer: bool = True
    follow_redirects: bool = True
    
    def set_header(self, key: str, value: str) -> None:
        """Set a header value."""
        self.headers[key] = value
    
    def update_headers(self, headers: Dict[str, str]) -> None:
        """Update multiple headers."""
        self.headers.update(headers)


class HttpClient(ABC):
    """Abstract base class for HTTP clients."""
    
    @abstractmethod
    def execute(self, request: HttpRequest) -> HttpResponse:
        """Execute an HTTP request and return the response."""
        pass
    
    @abstractmethod
    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        """Perform a GET request."""
        pass
    
    @abstractmethod
    def post(self, url: str, body: str = "", headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        """Perform a POST request."""
        pass
    
    @abstractmethod
    def put(self, url: str, body: str = "", headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        """Perform a PUT request."""
        pass
    
    @abstractmethod
    def delete(self, url: str, headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        """Perform a DELETE request."""
        pass
    
    @abstractmethod
    def set_default_timeout(self, timeout_ms: int) -> None:
        """Set the default timeout for all requests."""
        pass
    
    @abstractmethod
    def set_default_headers(self, headers: Dict[str, str]) -> None:
        """Set default headers for all requests."""
        pass
    
    @abstractmethod
    def set_client_certificate(self, cert_path: str, key_path: str) -> None:
        """Set client certificate for SSL authentication."""
        pass
    
    @abstractmethod
    def set_ca_certificate(self, ca_path: str) -> None:
        """Set CA certificate for SSL verification."""
        pass
    
    @abstractmethod
    def set_verify_peer(self, verify: bool) -> None:
        """Enable or disable SSL peer verification."""
        pass
    
    @abstractmethod
    def ping(self, url: str) -> bool:
        """Check connectivity to a URL."""
        pass