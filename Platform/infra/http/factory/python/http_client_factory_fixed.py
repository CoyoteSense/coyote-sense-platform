"""
HTTP Client Factory Module

This module provides factory functionality for creating HTTP clients based on
runtime mode, mirroring the C++ factory architecture.
"""

import os
import sys
from enum import Enum, auto
from typing import Optional

# Add the parent directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from interfaces.python.http_client import HttpClient


class RuntimeMode(Enum):
    """Runtime mode enumeration."""
    PRODUCTION = auto()
    RECORDING = auto()
    REPLAY = auto()
    SIMULATION = auto()
    DEBUG = auto()
    TESTING = auto()


class HttpClientFactory:
    """Factory for creating HTTP clients based on runtime mode."""
    
    @staticmethod
    def create_http_client() -> HttpClient:
        """Create HTTP client based on current runtime mode."""
        return HttpClientFactory.create_http_client_for_mode(
            HttpClientFactory.get_current_mode()
        )
    
    @staticmethod
    def create_http_client_for_mode(mode: RuntimeMode) -> HttpClient:
        """Create HTTP client for specific mode."""
        if mode == RuntimeMode.TESTING:
            from modes.mock.python.http_client_mock import HttpClientMock
            return HttpClientMock()
        else:
            # For all other modes, use the real implementation
            from modes.real.python.http_client_real import HttpClientReal
            return HttpClientReal()
    
    @staticmethod
    def get_current_mode() -> RuntimeMode:
        """Get current runtime mode from environment."""
        # Check COYOTE_RUNTIME_MODE first, then MODE
        mode_env = os.getenv("COYOTE_RUNTIME_MODE") or os.getenv("MODE")
        
        if mode_env is None:
            # Default to production mode if no environment variable is set
            return RuntimeMode.PRODUCTION
        
        return HttpClientFactory._parse_mode_from_string(mode_env)
    
    @staticmethod
    def _parse_mode_from_string(mode_str: str) -> RuntimeMode:
        """Parse runtime mode from string."""
        mode_lower = mode_str.lower()
        
        mode_mapping = {
            "production": RuntimeMode.PRODUCTION,
            "recording": RuntimeMode.RECORDING,
            "replay": RuntimeMode.REPLAY,
            "simulation": RuntimeMode.SIMULATION,
            "debug": RuntimeMode.DEBUG,
            "testing": RuntimeMode.TESTING,
        }
        
        return mode_mapping.get(mode_lower, RuntimeMode.PRODUCTION)


def make_http_client() -> HttpClient:
    """Convenience function for creating HTTP clients."""
    return HttpClientFactory.create_http_client()
