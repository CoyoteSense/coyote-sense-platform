"""
Basic tests for the refactored Security component
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python'))

from interfaces import (
    AuthConfig, AuthMode, 
    AuthToken, AuthResult, TokenStorage, Logger
)
from factory import create_auth_client
from datetime import datetime, timezone, timedelta


class TestAuthBasic:
    """Test basic auth functionality with refactored structure"""
    
    def test_config_creation(self):
        """Test that we can create a configuration"""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            auth_url="https://auth.example.com/oauth/authorize",
            token_url="https://auth.example.com/oauth/token"
        )
        
        assert config.client_id == "test_client"
        assert config.client_secret == "test_secret"
        assert config.auth_url == "https://auth.example.com/oauth/authorize"
        assert config.token_url == "https://auth.example.com/oauth/token"
        assert config.mode == AuthMode.REAL  # Default mode
        
    def test_mock_client_creation(self):
        """Test that we can create a mock authentication client"""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            auth_url="https://auth.example.com/oauth/authorize",
            token_url="https://auth.example.com/oauth/token",
            mode=AuthMode.MOCK
        )
        
        client = create_auth_client(config)
        assert client is not None
        assert hasattr(client, 'authenticate')
        assert hasattr(client, 'authenticate_async')
        assert hasattr(client, 'refresh_token')
        assert hasattr(client, 'refresh_token_async')
        
    def test_debug_client_creation(self):
        """Test that we can create a debug authentication client"""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            auth_url="https://auth.example.com/oauth/authorize",
            token_url="https://auth.example.com/oauth/token",
            mode=AuthMode.DEBUG
        )
        
        client = create_auth_client(config)
        assert client is not None
        assert hasattr(client, 'authenticate')
        assert hasattr(client, 'authenticate_async')
        
    def test_real_client_creation(self):
        """Test that we can create a real authentication client (needs aiohttp)"""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            auth_url="https://auth.example.com/oauth/authorize",
            token_url="https://auth.example.com/oauth/token",
            mode=AuthMode.REAL
        )
        
        client = create_auth_client(config)
        assert client is not None
        assert hasattr(client, 'authenticate')
        assert hasattr(client, 'authenticate_async')
        
    def test_token_creation(self):
        """Test that we can create and work with tokens"""
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        token = AuthToken(
            access_token="test_access_token",
            token_type="Bearer",
            expires_at=expires_at,
            refresh_token="test_refresh_token"
        )
        
        assert token.access_token == "test_access_token"
        assert token.token_type == "Bearer"
        assert token.refresh_token == "test_refresh_token"
        assert not token.is_expired()
        
        # Test token serialization
        token_dict = token.to_dict()
        assert token_dict['access_token'] == "test_access_token"
        assert token_dict['token_type'] == "Bearer"
        assert token_dict['refresh_token'] == "test_refresh_token"
        
        # Test token deserialization
        restored_token = AuthToken.from_dict(token_dict)
        assert restored_token.access_token == token.access_token
        assert restored_token.token_type == token.token_type
        assert restored_token.refresh_token == token.refresh_token
        
    def test_mock_authentication(self):
        """Test that mock authentication works"""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            auth_url="https://auth.example.com/oauth/authorize",
            token_url="https://auth.example.com/oauth/token",
            mode=AuthMode.MOCK
        )
        
        client = create_auth_client(config)
        result = client.authenticate()
        
        assert isinstance(result, AuthResult)
        assert result.success is True
        assert result.token is not None
        assert result.token.access_token == "mock_access_token"
        assert result.token.token_type == "Bearer"
        
    def test_debug_authentication(self):
        """Test that debug authentication works"""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            auth_url="https://auth.example.com/oauth/authorize",
            token_url="https://auth.example.com/oauth/token",
            mode=AuthMode.DEBUG
        )
        
        client = create_auth_client(config)
        result = client.authenticate()
        
        assert isinstance(result, AuthResult)
        assert result.success is True
        assert result.token is not None
        assert result.token.access_token == "debug_access_token"
        assert result.token.token_type == "Bearer"
