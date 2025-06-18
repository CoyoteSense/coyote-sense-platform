"""
Security Infrastructure Component - Python Interfaces

This module provides authentication and security interfaces for the CoyoteSense platform.
"""

from .auth_client import (
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

__all__ = [
    "AuthMode",
    "AuthClientConfig",
    "AuthToken",
    "AuthResult",
    "AuthServerInfo",
    "IAuthTokenStorage",
    "IAuthLogger",
    "IAuthClient",
    "InMemoryTokenStorage",
    "ConsoleAuthLogger",
    "NullAuthLogger",
    # Legacy aliases
    "OAuth2ClientConfig",
    "OAuth2Token",
    "OAuth2AuthResult",
    "OAuth2ServerInfo",
    "IOAuth2TokenStorage",
    "IOAuth2Logger",
    "IOAuth2AuthClient",
    "ConsoleOAuth2Logger",
    "NullOAuth2Logger",
]
