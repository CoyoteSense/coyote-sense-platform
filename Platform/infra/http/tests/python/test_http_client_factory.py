"""
Unit tests for HTTP Client Factory Fixed

This module contains unit tests for the HTTP client factory fixed functionality.
"""

import os
import sys
import pytest
from unittest.mock import patch

# Add the http directory to Python path for imports
http_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, http_root)

from src.python.factory.http_client_factory import HttpClientFactory, RuntimeMode
from modes.mock.python.http_client_mock import HttpClientMock
from modes.real.python.http_client_real import HttpClientReal


class TestHttpClientFactoryFixed:
    """Test cases for HTTP client factory fixed."""
    
    def setup_method(self):
        """Set up before each test method."""
        # Clear environment variables
        for env_var in ["COYOTE_RUNTIME_MODE", "MODE"]:
            if env_var in os.environ:
                del os.environ[env_var]
    
    def test_create_testing_client_explicitly(self):
        """Test creating a testing (mock) client explicitly."""
        client = HttpClientFactory.create_http_client_for_mode(RuntimeMode.TESTING)
        assert client is not None
        assert isinstance(client, HttpClientMock)
    
    def test_create_production_client_explicitly(self):
        """Test creating a production client explicitly."""
        client = HttpClientFactory.create_http_client_for_mode(RuntimeMode.PRODUCTION)
        assert client is not None
        assert isinstance(client, HttpClientReal)
    
    def test_create_client_with_testing_env_var(self):
        """Test creating client with COYOTE_RUNTIME_MODE=testing."""
        os.environ["COYOTE_RUNTIME_MODE"] = "testing"
        client = HttpClientFactory.create_http_client()
        assert client is not None
        assert isinstance(client, HttpClientMock)
        
        # Clean up
        del os.environ["COYOTE_RUNTIME_MODE"]
    
    def test_create_client_with_production_env_var(self):
        """Test creating client with COYOTE_RUNTIME_MODE=production."""
        os.environ["COYOTE_RUNTIME_MODE"] = "production"
        client = HttpClientFactory.create_http_client()
        assert client is not None
        assert isinstance(client, HttpClientReal)
        
        # Clean up
        del os.environ["COYOTE_RUNTIME_MODE"]
    
    def test_create_client_with_mode_env_var(self):
        """Test creating client with MODE=testing."""
        os.environ["MODE"] = "testing"
        client = HttpClientFactory.create_http_client()
        assert client is not None
        assert isinstance(client, HttpClientMock)
        
        # Clean up
        del os.environ["MODE"]
    
    def test_create_client_with_no_env_var(self):
        """Test creating client with no environment variable (should default to production)."""
        client = HttpClientFactory.create_http_client()
        assert client is not None
        assert isinstance(client, HttpClientReal)
    
    def test_create_client_with_unknown_mode(self):
        """Test creating client with unknown mode (should default to production)."""
        os.environ["COYOTE_RUNTIME_MODE"] = "unknown_mode"
        client = HttpClientFactory.create_http_client()
        assert client is not None
        assert isinstance(client, HttpClientReal)
        
        # Clean up
        del os.environ["COYOTE_RUNTIME_MODE"]
    
    def test_get_current_mode_no_env(self):
        """Test getting current mode with no environment variables."""
        mode = HttpClientFactory.get_current_mode()
        assert mode == RuntimeMode.PRODUCTION
    
    def test_get_current_mode_with_testing(self):
        """Test getting current mode with COYOTE_RUNTIME_MODE=testing."""
        os.environ["COYOTE_RUNTIME_MODE"] = "testing"
        mode = HttpClientFactory.get_current_mode()
        assert mode == RuntimeMode.TESTING
        
        # Clean up
        del os.environ["COYOTE_RUNTIME_MODE"]
    
    def test_case_insensitive_mode_parsing(self):
        """Test that mode parsing is case insensitive."""
        test_cases = [
            ("TESTING", RuntimeMode.TESTING),
            ("testing", RuntimeMode.TESTING),
            ("Testing", RuntimeMode.TESTING),
            ("PRODUCTION", RuntimeMode.PRODUCTION),
            ("production", RuntimeMode.PRODUCTION),
            ("Production", RuntimeMode.PRODUCTION),
        ]
        
        for mode_str, expected_mode in test_cases:
            os.environ["COYOTE_RUNTIME_MODE"] = mode_str
            mode = HttpClientFactory.get_current_mode()
            assert mode == expected_mode
            del os.environ["COYOTE_RUNTIME_MODE"]
    
    def test_invalid_mode_defaults_to_production(self):
        """Test that invalid mode strings default to production."""
        os.environ["COYOTE_RUNTIME_MODE"] = "invalid_mode"
        mode = HttpClientFactory.get_current_mode()
        assert mode == RuntimeMode.PRODUCTION
        
        # Clean up
        del os.environ["COYOTE_RUNTIME_MODE"]


class TestHttpClientFactoryFixedFunctionality:
    """Test the actual functionality of created clients."""
    
    def test_mock_client_functionality(self):
        """Test that mock client works as expected."""
        client = HttpClientFactory.create_http_client_for_mode(RuntimeMode.TESTING)
        
        # Test that it's a mock client
        assert isinstance(client, HttpClientMock)
        
        # Test basic functionality (mock should work without network)
        response = client.get("http://example.com/test")
        assert response is not None
        assert response.status_code == 200
    
    def test_real_client_creation(self):
        """Test that real client is created properly."""
        client = HttpClientFactory.create_http_client_for_mode(RuntimeMode.PRODUCTION)
        
        # Test that it's a real client
        assert isinstance(client, HttpClientReal)
        
        # Test that it has the expected interface
        assert hasattr(client, 'get')
        assert hasattr(client, 'post')
        assert hasattr(client, 'put')
        assert hasattr(client, 'delete')