"""
Authentication Interfaces and Types for Python

This module contains all the interface definitions and types for authentication
in the CoyoteSense platform. Supports multiple authentication standards:
- OAuth2 Client Credentials (RFC 6749)
- OAuth2 Authorization Code (RFC 6749)
- SAML 2.0 (planned)
- Custom authentication schemes

All authentication clients must implement the AuthClient interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional, Any, List


class AuthMode(Enum):
    """Authentication client operating modes"""
    MOCK = "mock"
    DEBUG = "debug"
    REAL = "real"


@dataclass
class AuthConfig:
    """Base configuration for authentication clients"""
    client_id: str
    client_secret: str
    auth_url: str
    token_url: str
    mode: AuthMode = AuthMode.REAL
    redirect_uri: Optional[str] = None
    scope: Optional[str] = None
    timeout: float = 30.0
    max_retries: int = 3
    
    # OAuth2 specific settings
    grant_type: str = "client_credentials"
    
    # Additional OAuth2 settings
    audience: Optional[str] = None
    resource: Optional[str] = None
    
    # PKCE settings for OAuth2 Authorization Code flow
    use_pkce: bool = False
    code_challenge_method: str = "S256"
    
    # Token management
    token_refresh_threshold: float = 300  # Refresh token 5 minutes before expiry
    auto_refresh: bool = True
    
    # Logging and debugging
    debug_mode: bool = False
    log_requests: bool = False
    log_responses: bool = False


@dataclass
class AuthToken:
    """Authentication token with metadata"""
    access_token: str
    token_type: str = "Bearer"
    expires_at: Optional[datetime] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    
    # Additional token metadata
    id_token: Optional[str] = None  # For OpenID Connect
    token_info: Optional[Dict[str, Any]] = None
    
    def is_expired(self) -> bool:
        """Check if the token is expired"""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= self.expires_at
    
    def expires_in(self) -> Optional[int]:
        """Get seconds until token expires"""
        if self.expires_at is None:
            return None
        delta = self.expires_at - datetime.now(timezone.utc)
        return max(0, int(delta.total_seconds()))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary for storage"""
        return {
            'access_token': self.access_token,
            'token_type': self.token_type,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'refresh_token': self.refresh_token,
            'scope': self.scope,
            'id_token': self.id_token,
            'token_info': self.token_info
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuthToken':
        """Create token from dictionary"""
        expires_at = None
        if data.get('expires_at'):
            expires_at = datetime.fromisoformat(data['expires_at'])
        
        return cls(
            access_token=data['access_token'],
            token_type=data.get('token_type', 'Bearer'),
            expires_at=expires_at,
            refresh_token=data.get('refresh_token'),
            scope=data.get('scope'),
            id_token=data.get('id_token'),
            token_info=data.get('token_info')
        )


@dataclass
class AuthResult:
    """Result of an authentication attempt"""
    success: bool
    token: Optional[AuthToken] = None
    error: Optional[str] = None
    error_description: Optional[str] = None
    error_code: Optional[str] = None
    
    # Additional result metadata
    state: Optional[str] = None  # For OAuth2 state parameter
    code: Optional[str] = None   # For OAuth2 authorization code
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            'success': self.success,
            'token': self.token.to_dict() if self.token else None,
            'error': self.error,
            'error_description': self.error_description,
            'error_code': self.error_code,
            'state': self.state,
            'code': self.code
        }


class TokenStorage(ABC):
    """Abstract base class for token storage implementations"""
    
    @abstractmethod
    def store_token(self, key: str, token: AuthToken) -> bool:
        """Store a token synchronously"""
        pass
    
    @abstractmethod
    def get_token(self, key: str) -> Optional[AuthToken]:
        """Retrieve a token synchronously"""
        pass
    
    @abstractmethod
    async def store_token_async(self, key: str, token: AuthToken) -> bool:
        """Store a token asynchronously"""
        pass
    
    @abstractmethod
    async def get_token_async(self, key: str) -> Optional[AuthToken]:
        """Retrieve a token asynchronously"""
        pass
    
    @abstractmethod
    def delete_token(self, key: str) -> bool:
        """Delete a token"""
        pass
    
    @abstractmethod
    def list_keys(self) -> List[str]:
        """List all stored token keys"""
        pass


class Logger(ABC):
    """Abstract base class for authentication logging"""
    
    @abstractmethod
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message"""
        pass
    
    @abstractmethod
    def info(self, message: str, **kwargs) -> None:
        """Log info message"""
        pass
    
    @abstractmethod
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message"""
        pass
    
    @abstractmethod
    def error(self, message: str, **kwargs) -> None:
        """Log error message"""
        pass


class AuthClient(ABC):
    """
    Abstract base class for all authentication clients.
    
    This interface defines the core authentication operations that all
    authentication clients must implement. It supports both synchronous
    and asynchronous operations.
    """
    
    def __init__(self, config: AuthConfig, 
                 token_storage: Optional[TokenStorage] = None,
                 logger: Optional[Logger] = None):
        """Initialize the authentication client"""
        self.config = config
        self.token_storage = token_storage
        self.logger = logger
    
    # Core authentication methods
    @abstractmethod
    async def authenticate_async(self, **kwargs) -> AuthResult:
        """
        Perform authentication asynchronously.
        
        Returns:
            AuthResult: Result of the authentication attempt
        """
        pass
    
    @abstractmethod
    def authenticate(self, **kwargs) -> AuthResult:
        """
        Perform authentication synchronously.
        
        Returns:
            AuthResult: Result of the authentication attempt
        """
        pass
    
    # Token management methods
    @abstractmethod
    async def refresh_token_async(self, refresh_token: str) -> AuthResult:
        """
        Refresh an access token asynchronously.
        
        Args:
            refresh_token: The refresh token to use
            
        Returns:
            AuthResult: Result containing the new token
        """
        pass
    
    @abstractmethod
    def refresh_token(self, refresh_token: str) -> AuthResult:
        """
        Refresh an access token synchronously.
        
        Args:
            refresh_token: The refresh token to use
            
        Returns:
            AuthResult: Result containing the new token
        """
        pass
    
    # Token validation and introspection
    @abstractmethod
    async def validate_token_async(self, token: str) -> Dict[str, Any]:
        """
        Validate and introspect a token asynchronously.
        
        Args:
            token: The token to validate
            
        Returns:
            Dict containing token information
        """
        pass
    
    @abstractmethod
    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate and introspect a token synchronously.
        
        Args:
            token: The token to validate
            
        Returns:
            Dict containing token information
        """
        pass
    
    # OAuth2 Authorization Code flow methods
    @abstractmethod
    def get_authorization_url(self, state: Optional[str] = None, **kwargs) -> str:
        """
        Get the authorization URL for OAuth2 Authorization Code flow.
        
        Args:
            state: Optional state parameter for security
            **kwargs: Additional parameters for the authorization URL
            
        Returns:
            str: The authorization URL
        """
        pass
    
    @abstractmethod
    async def exchange_code_async(self, code: str, state: Optional[str] = None) -> AuthResult:
        """
        Exchange authorization code for tokens asynchronously.
        
        Args:
            code: The authorization code received from the authorization server
            state: Optional state parameter for validation
            
        Returns:
            AuthResult: Result containing the tokens
        """
        pass
    
    @abstractmethod
    def exchange_code(self, code: str, state: Optional[str] = None) -> AuthResult:
        """
        Exchange authorization code for tokens synchronously.
        
        Args:
            code: The authorization code received from the authorization server
            state: Optional state parameter for validation
            
        Returns:
            AuthResult: Result containing the tokens
        """
        pass
    
    # Server discovery methods (for OAuth2/OpenID Connect)
    @abstractmethod
    async def discover_server_async(self) -> Dict[str, Any]:
        """
        Discover OAuth2/OpenID Connect server configuration asynchronously.
        
        Returns:
            Dict containing server configuration
        """
        pass
    
    @abstractmethod
    def discover_server(self) -> Dict[str, Any]:
        """
        Discover OAuth2/OpenID Connect server configuration synchronously.
        
        Returns:
            Dict containing server configuration
        """
        pass
    
    # Utility methods
    @abstractmethod
    async def revoke_token_async(self, token: str) -> bool:
        """
        Revoke a token asynchronously.
        
        Args:
            token: The token to revoke
            
        Returns:
            bool: True if revocation was successful
        """
        pass
    
    @abstractmethod
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token synchronously.
        
        Args:
            token: The token to revoke
            
        Returns:
            bool: True if revocation was successful
        """
        pass
    
    def get_stored_token(self, key: str) -> Optional[AuthToken]:
        """Get a stored token"""
        if self.token_storage:
            return self.token_storage.get_token(key)
        return None
    
    def store_token(self, key: str, token: AuthToken) -> bool:
        """Store a token"""
        if self.token_storage:
            return self.token_storage.store_token(key, token)
        return False
    
    def log_debug(self, message: str, **kwargs) -> None:
        """Log a debug message"""
        if self.logger:
            self.logger.debug(message, **kwargs)
    
    def log_info(self, message: str, **kwargs) -> None:
        """Log an info message"""
        if self.logger:
            self.logger.info(message, **kwargs)
    
    def log_warning(self, message: str, **kwargs) -> None:
        """Log a warning message"""
        if self.logger:
            self.logger.warning(message, **kwargs)
    
    def log_error(self, message: str, **kwargs) -> None:
        """Log an error message"""
        if self.logger:
            self.logger.error(message, **kwargs)


# Export all public interfaces and types
__all__ = [
    'AuthMode',
    'AuthConfig', 
    'AuthToken',
    'AuthResult',
    'TokenStorage',
    'Logger',
    'AuthClient'
]
