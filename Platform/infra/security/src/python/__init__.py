"""
CoyoteSense Security Infrastructure Component - Python

This package provides authentication and security functionality for the CoyoteSense platform.
Supports multiple authentication standards including OAuth2, JWT Bearer, and mTLS.

Example usage:

    from coyote_infra_security import AuthClientConfig, AuthMode, create_auth_client
    
    # Create configuration
    config = AuthClientConfig(
        server_url="https://auth.example.com",
        client_id="your-client-id",
        client_secret="your-client-secret",
        auth_mode=AuthMode.CLIENT_CREDENTIALS,
        default_scopes=["trading", "analytics"]
    )
    
    # Create client (real mode)
    auth_client = create_auth_client(config, mode="real")
    
    # Authenticate
    result = auth_client.authenticate_client_credentials()
    if result.success:
        token = result.token
        print(f"Access token: {token.access_token}")
    
    # Create mock client for testing
    mock_client = create_auth_client(config, mode="mock")
"""

from .interfaces import (
    AuthMode,
    AuthClientConfig,
    AuthToken,
    AuthResult,
    AuthServerInfo,
    IAuthTokenStorage,
    IAuthLogger,
    IAuthClient,
    InMemoryTokenStorage,
    ConsoleAuthLogger,
    NullAuthLogger,
    # Legacy aliases
    OAuth2ClientConfig,
    OAuth2Token,
    OAuth2AuthResult,
    OAuth2ServerInfo,
    IOAuth2TokenStorage,
    IOAuth2Logger,
    IOAuth2AuthClient,
    ConsoleOAuth2Logger,
    NullOAuth2Logger,
)

from .factory import (
    AuthClientFactory,
    create_auth_client,
    # Legacy aliases
    OAuth2ClientFactory,
    create_oauth2_client,
)

from .impl import (
    RealAuthClient,
    MockAuthClient,
    DebugAuthClient,
    DebugAuthLogger,
)

__version__ = "1.0.0"
__author__ = "CoyoteSense Platform Team"

__all__ = [
    # Core interfaces and types
    "AuthMode",
    "AuthClientConfig", 
    "AuthToken",
    "AuthResult",
    "AuthServerInfo",
    "IAuthTokenStorage",
    "IAuthLogger", 
    "IAuthClient",
    
    # Concrete implementations
    "InMemoryTokenStorage",
    "ConsoleAuthLogger",
    "NullAuthLogger",
    "RealAuthClient",
    "MockAuthClient",
    "DebugAuthClient",
    "DebugAuthLogger",
    
    # Factory functions
    "AuthClientFactory",
    "create_auth_client",
    
    # Legacy aliases for backward compatibility
    "OAuth2ClientConfig",
    "OAuth2Token", 
    "OAuth2AuthResult",
    "OAuth2ServerInfo",
    "IOAuth2TokenStorage",
    "IOAuth2Logger",
    "IOAuth2AuthClient",
    "ConsoleOAuth2Logger",
    "NullOAuth2Logger",
    "OAuth2ClientFactory",
    "create_oauth2_client",
]
