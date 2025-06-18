"""
Security Infrastructure Component - Python Factory

This module provides factory functions for creating security-related clients and services.
"""

from .auth_client_factory import (
    AuthClientFactory,
    create_auth_client,
    # Legacy aliases
    OAuth2ClientFactory,
    create_oauth2_client,
)

__all__ = [
    "AuthClientFactory",
    "create_auth_client",
    # Legacy aliases
    "OAuth2ClientFactory", 
    "create_oauth2_client",
]
