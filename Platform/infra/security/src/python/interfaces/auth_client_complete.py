"""
Authentication Interfaces and Types for Python

This module contains all the interface definitions and types for authentication
in the CoyoteSense platform. Supports multiple authentication standards:
- OAuth2 Client Credentials (RFC 6749)
- OAuth2 Authorization Code (RFC 6749) 
- OAuth2 + PKCE (RFC 7636)
- JWT Bearer (RFC 7523)
- mTLS Client Credentials (RFC 8705)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Union
from datetime import datetime
import asyncio


class AuthMode(Enum):
    """Authentication modes supported by the platform"""
    
    CLIENT_CREDENTIALS = "client_credentials"
    """Standard OAuth2 client credentials flow"""
    
    CLIENT_CREDENTIALS_MTLS = "client_credentials_mtls"
    """Client credentials with mutual TLS authentication"""
    
    JWT_BEARER = "jwt_bearer"
    """JWT Bearer assertion flow"""
    
    AUTHORIZATION_CODE = "authorization_code"
    """Authorization code flow"""
    
    AUTHORIZATION_CODE_PKCE = "authorization_code_pkce"
    """Authorization code flow with PKCE"""


@dataclass
class AuthClientConfig:
    """Authentication client configuration"""
    
    # Required fields
    server_url: str
    client_id: str
    
    # Authentication mode
    auth_mode: AuthMode = AuthMode.CLIENT_CREDENTIALS
    
    # Basic OAuth2 settings
    client_secret: Optional[str] = None
    default_scopes: List[str] = field(default_factory=list)
    
    # mTLS settings
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    ca_cert_path: Optional[str] = None
    
    # JWT Bearer settings
    jwt_signing_key_path: Optional[str] = None
    jwt_algorithm: str = "RS256"
    jwt_issuer: Optional[str] = None
    jwt_audience: Optional[str] = None
    
    # Authorization Code settings
    redirect_uri: Optional[str] = None
    use_pkce: bool = True
    
    # Token management
    refresh_buffer_seconds: int = 300  # 5 minutes
    auto_refresh: bool = True
    max_retry_attempts: int = 3
    retry_delay_ms: int = 1000
    
    # HTTP settings
    timeout_ms: int = 30000
    verify_ssl: bool = True
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    def is_client_credentials_mode(self) -> bool:
        """Check if using client credentials mode"""
        return self.auth_mode == AuthMode.CLIENT_CREDENTIALS
    
    def is_mtls_mode(self) -> bool:
        """Check if using mTLS mode"""
        return self.auth_mode == AuthMode.CLIENT_CREDENTIALS_MTLS
    
    def is_jwt_bearer_mode(self) -> bool:
        """Check if using JWT Bearer mode"""
        return self.auth_mode == AuthMode.JWT_BEARER
    
    def is_authorization_code_mode(self) -> bool:
        """Check if using any authorization code mode"""
        return self.auth_mode in (AuthMode.AUTHORIZATION_CODE, AuthMode.AUTHORIZATION_CODE_PKCE)
    
    def requires_certificates(self) -> bool:
        """Check if certificates are required for this mode"""
        return self.is_mtls_mode()
    
    def requires_client_secret(self) -> bool:
        """Check if client secret is required for this mode"""
        return self.is_client_credentials_mode() or self.is_mtls_mode()
    
    def requires_jwt_key(self) -> bool:
        """Check if JWT key is required for this mode"""
        return self.is_jwt_bearer_mode()
    
    def requires_redirect_uri(self) -> bool:
        """Check if redirect URI is required for this mode"""
        return self.is_authorization_code_mode()
    
    def is_valid(self) -> bool:
        """Validate configuration for the selected authentication mode"""
        if not self.client_id or not self.server_url:
            return False
        
        if self.auth_mode == AuthMode.CLIENT_CREDENTIALS:
            return bool(self.client_secret)
        elif self.auth_mode == AuthMode.CLIENT_CREDENTIALS_MTLS:
            return bool(self.client_secret and self.client_cert_path and self.client_key_path)
        elif self.auth_mode == AuthMode.JWT_BEARER:
            return bool(self.jwt_signing_key_path)
        elif self.auth_mode in (AuthMode.AUTHORIZATION_CODE, AuthMode.AUTHORIZATION_CODE_PKCE):
            return bool(self.redirect_uri)
        else:
            return False


@dataclass
class AuthToken:
    """Authentication token information"""
    
    access_token: str
    token_type: str = "Bearer"
    expires_at: Optional[datetime] = None
    refresh_token: Optional[str] = None
    scopes: List[str] = field(default_factory=list)
    id_token: Optional[str] = None
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired"""
        if self.expires_at is None:
            return False
        return datetime.utcnow() >= self.expires_at
    
    def needs_refresh(self, buffer_seconds: int = 300) -> bool:
        """Check if token needs refresh (within buffer time)"""
        if self.expires_at is None:
            return False
        return datetime.utcnow().timestamp() + buffer_seconds >= self.expires_at.timestamp()
    
    def get_authorization_header(self) -> str:
        """Get authorization header value"""
        return f"{self.token_type} {self.access_token}"


@dataclass
class AuthResult:
    """Authentication result"""
    
    success: bool
    token: Optional[AuthToken] = None
    error_code: Optional[str] = None
    error_description: Optional[str] = None
    error_details: Optional[str] = None
    
    @classmethod
    def success_result(cls, token: AuthToken) -> 'AuthResult':
        """Create success result"""
        return cls(success=True, token=token)
    
    @classmethod
    def error_result(cls, error_code: str, error_description: Optional[str] = None, 
                    error_details: Optional[str] = None) -> 'AuthResult':
        """Create error result"""
        return cls(
            success=False,
            error_code=error_code,
            error_description=error_description,
            error_details=error_details
        )


@dataclass
class AuthServerInfo:
    """Authentication server information"""
    
    authorization_endpoint: str
    token_endpoint: str
    introspection_endpoint: Optional[str] = None
    revocation_endpoint: Optional[str] = None
    grant_types_supported: List[str] = field(default_factory=list)
    scopes_supported: List[str] = field(default_factory=list)


class IAuthTokenStorage(ABC):
    """Authentication token storage interface"""
    
    @abstractmethod
    async def store_token_async(self, client_id: str, token: AuthToken) -> None:
        """Store a token for a client"""
        pass
    
    @abstractmethod
    def get_token(self, client_id: str) -> Optional[AuthToken]:
        """Retrieve a token for a client"""
        pass
    
    @abstractmethod
    def clear_token(self, client_id: str) -> None:
        """Clear stored token for a client"""
        pass
    
    @abstractmethod
    def clear_all_tokens(self) -> None:
        """Clear all stored tokens"""
        pass


class IAuthLogger(ABC):
    """Authentication logger interface"""
    
    @abstractmethod
    def log_info(self, message: str) -> None:
        """Log information message"""
        pass
    
    @abstractmethod
    def log_error(self, message: str) -> None:
        """Log error message"""
        pass
    
    @abstractmethod
    def log_debug(self, message: str) -> None:
        """Log debug message"""
        pass


class IAuthClient(ABC):
    """Authentication client interface
    
    Supports multiple authentication standards:
    - OAuth2 Client Credentials (RFC 6749)
    - OAuth2 Authorization Code (RFC 6749) 
    - OAuth2 + PKCE (RFC 7636)
    - JWT Bearer (RFC 7523)
    - mTLS Client Credentials (RFC 8705)
    """
    
    @abstractmethod
    async def authenticate_client_credentials_async(
        self, scopes: Optional[List[str]] = None
    ) -> AuthResult:
        """Authenticate using Client Credentials flow"""
        pass
    
    @abstractmethod
    async def authenticate_jwt_bearer_async(
        self, subject: Optional[str] = None, scopes: Optional[List[str]] = None
    ) -> AuthResult:
        """Authenticate using JWT Bearer flow"""
        pass
    
    @abstractmethod
    async def authenticate_authorization_code_async(
        self, authorization_code: str, redirect_uri: str, code_verifier: Optional[str] = None
    ) -> AuthResult:
        """Authenticate using Authorization Code flow"""
        pass
    
    @abstractmethod
    async def start_authorization_code_flow_async(
        self, redirect_uri: str, scopes: Optional[List[str]] = None, state: Optional[str] = None
    ) -> tuple[str, str, str]:
        """Start Authorization Code + PKCE flow (returns authorization URL, code verifier, state)"""
        pass
    
    @abstractmethod
    async def refresh_token_async(self, refresh_token: str) -> AuthResult:
        """Refresh access token using refresh token"""
        pass
    
    @abstractmethod
    async def get_valid_token_async(self) -> Optional[AuthToken]:
        """Get current valid token (automatically refreshes if needed)"""
        pass
    
    @abstractmethod
    async def revoke_token_async(self, token: str, token_type_hint: Optional[str] = None) -> bool:
        """Revoke a token"""
        pass
    
    @abstractmethod
    async def introspect_token_async(self, token: str) -> bool:
        """Introspect a token"""
        pass
    
    @abstractmethod
    async def test_connection_async(self) -> bool:
        """Test connection to authentication server"""
        pass
    
    @abstractmethod
    async def get_server_info_async(self) -> Optional[AuthServerInfo]:
        """Get authentication server information"""
        pass
    
    @abstractmethod
    def clear_tokens(self) -> None:
        """Clear stored tokens"""
        pass
    
    @property
    @abstractmethod
    def current_token(self) -> Optional[AuthToken]:
        """Current token (if any)"""
        pass
    
    @property
    @abstractmethod
    def is_authenticated(self) -> bool:
        """Whether client has valid authentication"""
        pass
    
    # Synchronous versions for compatibility
    def authenticate_client_credentials(self, scopes: Optional[List[str]] = None) -> AuthResult:
        """Authenticate using Client Credentials flow (sync)"""
        return self._run_async_safely(self.authenticate_client_credentials_async(scopes))
    
    def authenticate_jwt_bearer(self, subject: Optional[str] = None, scopes: Optional[List[str]] = None) -> AuthResult:
        """Authenticate using JWT Bearer flow (sync)"""
        return self._run_async_safely(self.authenticate_jwt_bearer_async(subject, scopes))
    
    def authenticate_authorization_code(self, authorization_code: str, redirect_uri: str, code_verifier: Optional[str] = None) -> AuthResult:
        """Authenticate using Authorization Code flow (sync)"""
        return self._run_async_safely(self.authenticate_authorization_code_async(authorization_code, redirect_uri, code_verifier))
    
    def refresh_token(self, refresh_token: str) -> AuthResult:
        """Refresh access token using refresh token (sync)"""
        return self._run_async_safely(self.refresh_token_async(refresh_token))
    
    def get_valid_token(self) -> Optional[AuthToken]:
        """Get current valid token (sync)"""
        return self._run_async_safely(self.get_valid_token_async())
    
    def revoke_token(self, token: str, token_type_hint: Optional[str] = None) -> bool:
        """Revoke a token (sync)"""
        return self._run_async_safely(self.revoke_token_async(token, token_type_hint))
    
    def introspect_token(self, token: str) -> bool:
        """Introspect a token (sync)"""
        return self._run_async_safely(self.introspect_token_async(token))
    
    def test_connection(self) -> bool:
        """Test connection to authentication server (sync)"""
        return self._run_async_safely(self.test_connection_async())
    
    def get_server_info(self) -> Optional[AuthServerInfo]:
        """Get authentication server information (sync)"""
        return self._run_async_safely(self.get_server_info_async())
    
    def _run_async_safely(self, coro):
        """Safely run async coroutine, handling existing event loop cases"""
        try:
            # Try to get the current event loop
            loop = asyncio.get_running_loop()
            # If we're already in an event loop, we need to create a new thread
            import concurrent.futures
            import threading
            
            def run_in_thread():
                # Create a new event loop for this thread
                new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(new_loop)
                try:
                    return new_loop.run_until_complete(coro)
                finally:
                    new_loop.close()
            
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(run_in_thread)
                return future.result(timeout=30)  # 30 second timeout to prevent hangs
                
        except RuntimeError:
            # No event loop running, safe to use asyncio.run()
            return asyncio.run(coro)


# Concrete implementations

class InMemoryTokenStorage(IAuthTokenStorage):
    """In-memory token storage implementation"""
    
    def __init__(self):
        self._tokens: Dict[str, AuthToken] = {}
    
    async def store_token_async(self, client_id: str, token: AuthToken) -> None:
        self._tokens[client_id] = token
    
    def get_token(self, client_id: str) -> Optional[AuthToken]:
        return self._tokens.get(client_id)
    
    def clear_token(self, client_id: str) -> None:
        self._tokens.pop(client_id, None)
    
    def clear_all_tokens(self) -> None:
        self._tokens.clear()


class ConsoleAuthLogger(IAuthLogger):
    """Console logger implementation"""
    
    def __init__(self, prefix: str = "Auth"):
        self.prefix = prefix
    
    def log_info(self, message: str) -> None:
        print(f"[{datetime.utcnow().isoformat()}] [{self.prefix}] INFO: {message}")
    
    def log_error(self, message: str) -> None:
        print(f"[{datetime.utcnow().isoformat()}] [{self.prefix}] ERROR: {message}")
    
    def log_debug(self, message: str) -> None:
        print(f"[{datetime.utcnow().isoformat()}] [{self.prefix}] DEBUG: {message}")


class NullAuthLogger(IAuthLogger):
    """Null logger implementation (no logging)"""
    
    def log_info(self, message: str) -> None:
        pass
    
    def log_error(self, message: str) -> None:
        pass
    
    def log_debug(self, message: str) -> None:
        pass


# Legacy aliases for backward compatibility
OAuth2ClientConfig = AuthClientConfig
OAuth2Token = AuthToken  
OAuth2AuthResult = AuthResult
OAuth2ServerInfo = AuthServerInfo
IOAuth2TokenStorage = IAuthTokenStorage
IOAuth2Logger = IAuthLogger
IOAuth2AuthClient = IAuthClient
ConsoleOAuth2Logger = ConsoleAuthLogger
NullOAuth2Logger = NullAuthLogger
