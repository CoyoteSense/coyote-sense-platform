"""
Security Infrastructure Component - Python Interfaces

This module provides authentication and security interfaces for the CoyoteSense platform.
"""

from .auth_client import (
    AuthMode,
    AuthConfig,
    AuthToken,
    AuthResult,
    TokenStorage,
    Logger,
    AuthClient
)

# Export all interfaces
__all__ = [
    'AuthMode',
    'AuthConfig',
    'AuthToken', 
    'AuthResult',
    'TokenStorage',
    'Logger',
    'AuthClient'
]
