"""
Basic functionality test for OAuth2 Authentication Client Python implementation
"""

import pytest
from unittest.mock import patch, Mock
import sys
import os

# Use direct import path that works
sys.path.append('../../src/python/impl/real')
from auth_client import (
    OAuth2Token,
    OAuth2AuthResult,
    OAuth2TokenStorage,
    OAuth2Logger,
    OAuth2ClientConfig,
    OAuth2AuthClient,
    InMemoryTokenStorage,
    NullOAuth2Logger
)


def test_oauth2_client_creation():
    """Test basic OAuth2 client creation"""
    config = OAuth2ClientConfig(
        server_url="https://test-auth.example.com",
        client_id="test-client-id",
        client_secret="test-client-secret"
    )
    
    client = OAuth2AuthClient(config)
    assert client.config.server_url == "https://test-auth.example.com"
    assert client.config.client_id == "test-client-id"
    assert client.config.client_secret == "test-client-secret"
    assert isinstance(client.token_storage, InMemoryTokenStorage)
    assert isinstance(client.logger, NullOAuth2Logger)


def test_oauth2_token_creation():
    """Test OAuth2 token creation and properties"""
    from datetime import datetime, timedelta
    
    expires_at = datetime.utcnow() + timedelta(seconds=3600)
    token = OAuth2Token(
        access_token="test-token",
        token_type="Bearer",
        expires_at=expires_at,
        scopes=["read", "write"]
    )
    
    assert token.access_token == "test-token"
    assert token.token_type == "Bearer"
    assert token.expires_at == expires_at
    assert token.scopes == ["read", "write"]
    assert not token.is_expired  # Should not be expired
    assert token.get_authorization_header() == "Bearer test-token"


def test_oauth2_auth_result():
    """Test OAuth2 authentication result"""
    from datetime import datetime, timedelta
    
    # Test success result
    token = OAuth2Token(
        access_token="success-token",
        expires_at=datetime.utcnow() + timedelta(seconds=3600)
    )
    
    success_result = OAuth2AuthResult.success(token)
    assert success_result.is_success is True
    assert success_result.token == token
    assert success_result.error_code is None
    
    # Test error result
    error_result = OAuth2AuthResult.error("invalid_client", "Client authentication failed")
    assert error_result.is_success is False
    assert error_result.token is None
    assert error_result.error_code == "invalid_client"
    assert error_result.error_description == "Client authentication failed"


def test_in_memory_token_storage():
    """Test in-memory token storage"""
    from datetime import datetime, timedelta
    import asyncio
    
    async def test_storage():
        storage = InMemoryTokenStorage()
        
        # Create test token
        token = OAuth2Token(
            access_token="stored-token",
            expires_at=datetime.utcnow() + timedelta(seconds=3600)
        )
        
        # Store token
        await storage.store_token("test-client", token)
        
        # Retrieve token
        retrieved = storage.get_token("test-client")
        assert retrieved is not None
        assert retrieved.access_token == "stored-token"
        
        # Clear token
        storage.clear_token("test-client")
        assert storage.get_token("test-client") is None
    
    asyncio.run(test_storage())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
