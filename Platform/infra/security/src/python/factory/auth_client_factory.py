"""
Authentication Client Factory for Python

This module provides a factory for creating authentication clients based on 
runtime configuration and mode requirements.
"""

from typing import Optional, Dict, Any, List
import sys
import os

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from interfaces.auth_client import AuthClient, AuthConfig, TokenStorage, Logger, AuthMode
from impl.mock.auth_client_mock import MockAuthClient
from impl.debug.auth_client_debug import DebugAuthClient


class AuthClientFactory:
    """Factory for creating authentication clients based on runtime mode."""
    
    @staticmethod
    def create_client(
        config: AuthConfig,
        mode: str = None,
        token_storage: Optional[TokenStorage] = None,
        logger: Optional[Logger] = None
    ) -> AuthClient:
        """
        Create an authentication client based on the specified mode.
        
        Args:
            config: Authentication client configuration
            mode: Runtime mode ("mock", "debug") - if None, uses config.mode
            token_storage: Optional token storage implementation
            logger: Optional logger implementation
            
        Returns:
            AuthClient: Authentication client instance
            
        Raises:
            ValueError: If mode is not supported
        """
        if mode is None:
            if hasattr(config.mode, 'value'):
                mode = config.mode.value
            else:
                mode = str(config.mode)
        
        mode = mode.lower()
        
        if mode == "mock":
            return MockAuthClient(config, token_storage, logger)
        elif mode == "debug":
            return DebugAuthClient(config, token_storage, logger)
        elif mode == "real":
            raise ValueError("Real mode not yet available - use mock or debug mode")
        else:
            raise ValueError(f"Unsupported authentication mode: {mode}")
    
    @staticmethod
    def get_supported_modes() -> List[str]:
        """Get list of supported runtime modes."""
        return ["mock", "debug"]


def create_auth_client(
    config: AuthConfig,
    token_storage: Optional[TokenStorage] = None,
    logger: Optional[Logger] = None
) -> AuthClient:
    """
    Create an authentication client (convenience function).
    
    This is a wrapper around AuthClientFactory.create_client() for 
    backward compatibility and ease of use.
    
    Args:
        config: Authentication configuration
        token_storage: Optional token storage implementation
        logger: Optional logger implementation
        
    Returns:
        AuthClient: An authentication client instance
    """
    return AuthClientFactory.create_client(config, None, token_storage, logger)


# Legacy aliases for backward compatibility
OAuth2ClientFactory = AuthClientFactory
create_oauth2_client = create_auth_client


# Export the factory and convenience function
__all__ = [
    'AuthClientFactory',
    'create_auth_client',
    'OAuth2ClientFactory',
    'create_oauth2_client'
]
