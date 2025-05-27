"""
HTTP Client Factory Module

This module provides factory functionality for creating HTTP clients,
mirroring the C++ factory architecture but using Python conventions.
"""

import os
import sys
from enum import Enum, auto
from typing import Optional

# Add the http directory to Python path for imports
http_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, http_root)

from interfaces.python.http_client import HttpClient


class RuntimeMode(Enum):
    """Runtime mode enumeration for different HTTP client implementations."""
    PRODUCTION = auto()
    REAL = auto()  # Alias for PRODUCTION
    MOCK = auto()
    TEST = auto()  # Alias for MOCK
    DEBUG = auto()
    SIMULATION = auto()


class HttpClientFactory:
    """Factory class for creating HTTP clients based on runtime mode."""
    
    @staticmethod
    def create_client(mode: RuntimeMode) -> HttpClient:
        """
        Create an HTTP client based on the specified runtime mode.
        
        Args:
            mode: The runtime mode determining which client implementation to create
            
        Returns:
            HttpClient: An instance of the appropriate HTTP client implementation
            
        Raises:
            ValueError: If the mode is not supported
        """
        if mode in (RuntimeMode.PRODUCTION, RuntimeMode.REAL):
            from modes.real.python.http_client_real import HttpClientReal
            return HttpClientReal()
        elif mode in (RuntimeMode.MOCK, RuntimeMode.TEST):
            from modes.mock.python.http_client_mock import HttpClientMock
            return HttpClientMock()
        elif mode == RuntimeMode.DEBUG:
            # For debug mode, use real client with additional logging
            from modes.real.python.http_client_real import HttpClientReal
            return HttpClientReal()
        elif mode == RuntimeMode.SIMULATION:
            # For simulation mode, use mock client
            from modes.mock.python.http_client_mock import HttpClientMock
            return HttpClientMock()
        else:
            raise ValueError(f"Unsupported runtime mode: {mode}")


def make_http_client(mode: Optional[RuntimeMode] = None) -> HttpClient:
    """
    Convenience function to create an HTTP client.
    
    If no mode is specified, attempts to determine mode from environment variables:
    - COYOTE_RUNTIME_MODE
    - MODE
    
    Args:
        mode: Optional runtime mode. If None, will be determined from environment
        
    Returns:
        HttpClient: An instance of the appropriate HTTP client implementation
    """
    if mode is None:
        # Try to get mode from environment variables
        env_mode = os.getenv('COYOTE_RUNTIME_MODE') or os.getenv('MODE')
        if env_mode:
            mode_str = env_mode.upper()
            if mode_str in ('PRODUCTION', 'REAL'):
                mode = RuntimeMode.REAL
            elif mode_str in ('MOCK', 'TEST', 'TESTING'):  # added 'TESTING'
                mode = RuntimeMode.MOCK
            elif mode_str == 'DEBUG':
                mode = RuntimeMode.DEBUG
            elif mode_str == 'SIMULATION':
                mode = RuntimeMode.SIMULATION
            else:
                mode = RuntimeMode.REAL  # Default fallback
        else:
            mode = RuntimeMode.REAL  # Default fallback
    
    return HttpClientFactory.create_client(mode)