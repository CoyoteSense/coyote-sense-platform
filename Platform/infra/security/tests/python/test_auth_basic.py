"""
Basic tests for the Security Infrastructure Component

These tests verify the basic functionality of the authentication clients.
"""

import pytest
import asyncio
from datetime import datetime, timedelta

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python'))

from interfaces import (
    AuthConfig, AuthMode, 
    AuthToken, AuthResult, TokenStorage, Logger
)
from factory import create_auth_client
from impl.real.auth_client import InMemoryTokenStorage


class TestAuthConfig:
    """Test authentication client configuration"""
    
    def test_config_creation(self):
        """Test basic configuration creation"""
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
        
    def test_config_with_mode(self):
        """Test configuration with different modes"""
        config = AuthConfig(
            client_id="test_client",
            client_secret="test_secret",
            auth_url="https://auth.example.com/oauth/authorize",
            token_url="https://auth.example.com/oauth/token",
            mode=AuthMode.MOCK
        )
        
        assert config.mode == AuthMode.MOCK
    
    def test_jwt_bearer_config(self):
        """Test JWT Bearer configuration"""
        config = AuthConfig(
            server_url="https://auth.example.com",
            client_id="test-client",
            auth_mode=AuthMode.JWT_BEARER,
            jwt_signing_key_path="/path/to/key.pem"
        )
        
        assert config.is_valid()
        assert config.is_jwt_bearer_mode()
        assert not config.is_client_credentials_mode()
        assert config.requires_jwt_key()
        assert not config.requires_client_secret()
    
    def test_invalid_config(self):
        """Test invalid configuration"""
        # Missing client_secret for client credentials
        config = AuthConfig(
            server_url="https://auth.example.com",
            client_id="test-client",
            auth_mode=AuthMode.CLIENT_CREDENTIALS
            # client_secret is missing
        )
        
        assert not config.is_valid()


class TestAuthToken:
    """Test authentication token functionality"""
    
    def test_token_creation(self):
        """Test token creation"""
        expires_at = datetime.utcnow() + timedelta(hours=1)
        token = AuthToken(
            access_token="test-token",
            token_type="Bearer",
            expires_at=expires_at,
            scopes=["read", "write"]
        )
        
        assert token.access_token == "test-token"
        assert token.token_type == "Bearer"
        assert not token.is_expired
        assert token.get_authorization_header() == "Bearer test-token"
    
    def test_token_expiry(self):
        """Test token expiry logic"""
        # Expired token
        expires_at = datetime.utcnow() - timedelta(minutes=1)
        expired_token = AuthToken(
            access_token="expired-token",
            expires_at=expires_at
        )
        
        assert expired_token.is_expired
        
        # Token needing refresh
        expires_at = datetime.utcnow() + timedelta(minutes=2)
        refresh_token = AuthToken(
            access_token="refresh-needed-token",
            expires_at=expires_at
        )
        
        assert not refresh_token.is_expired
        assert refresh_token.needs_refresh(buffer_seconds=300)  # 5 minutes buffer


class TestTokenStorage:
    """Test token storage functionality"""
    
    def test_in_memory_storage(self):
        """Test in-memory token storage"""
        storage = InMemoryTokenStorage()
        
        token = AuthToken(access_token="test-token")
        client_id = "test-client"
        
        # Store token
        asyncio.run(storage.store_token_async(client_id, token))
        
        # Retrieve token
        retrieved_token = storage.get_token(client_id)
        assert retrieved_token is not None
        assert retrieved_token.access_token == "test-token"
        
        # Clear token
        storage.clear_token(client_id)
        assert storage.get_token(client_id) is None


class TestMockAuthClient:
    """Test mock authentication client"""
    
    @pytest.fixture
    def config(self):
        """Test configuration"""
        return AuthConfig(
            server_url="https://auth.example.com",
            client_id="test-client",
            client_secret="test-secret",
            auth_mode=AuthMode.CLIENT_CREDENTIALS
        )
    
    @pytest.fixture
    def mock_client(self, config):
        """Mock authentication client"""
        return create_auth_client(
            config,
            mode="mock",
            logger=NullAuthLogger()
        )
    
    @pytest.mark.asyncio
    async def test_mock_client_credentials(self, mock_client):
        """Test mock client credentials authentication"""
        result = await mock_client.authenticate_client_credentials_async(
            scopes=["read", "write"]
        )
        
        assert result.success
        assert result.token is not None
        assert result.token.access_token.startswith("mock_access_token_")
        assert result.token.scopes == ["read", "write"]
        assert mock_client.is_authenticated
    
    @pytest.mark.asyncio
    async def test_mock_connection_test(self, mock_client):
        """Test mock connection test"""
        result = await mock_client.test_connection_async()
        assert result is True
    
    @pytest.mark.asyncio
    async def test_mock_server_info(self, mock_client):
        """Test mock server info retrieval"""
        server_info = await mock_client.get_server_info_async()
        assert server_info is not None
        assert server_info.token_endpoint.endswith("/token")
        assert "client_credentials" in server_info.grant_types_supported
    
    @pytest.mark.asyncio
    async def test_mock_failure_simulation(self, config):
        """Test mock failure simulation"""
        # Create mock client configured to fail
        failing_client = create_auth_client(
            config,
            mode="mock",
            logger=NullAuthLogger(),
            custom_config={"should_fail": True}
        )
        
        result = await failing_client.authenticate_client_credentials_async()
        assert not result.success
        assert result.error_code is not None


class TestDebugAuthClient:
    """Test debug authentication client"""
    
    @pytest.fixture
    def config(self):
        """Test configuration"""
        return AuthConfig(
            server_url="https://auth.example.com",
            client_id="debug-client",
            client_secret="debug-secret",
            auth_mode=AuthMode.CLIENT_CREDENTIALS
        )
    
    @pytest.fixture
    def debug_client(self, config):
        """Debug authentication client"""
        return create_auth_client(
            config,
            mode="debug",
            logger=NullAuthLogger(),
            custom_config={
                "trace_requests": True,
                "performance_tracking": True
            }
        )
    
    @pytest.mark.asyncio
    async def test_debug_client_functionality(self, debug_client):
        """Test debug client basic functionality"""
        result = await debug_client.authenticate_client_credentials_async()
        
        assert result.success
        assert debug_client.is_authenticated
        
        # Test debug-specific methods
        if hasattr(debug_client, 'get_performance_stats'):
            stats = debug_client.get_performance_stats()
            assert isinstance(stats, dict)
            assert "authenticate_client_credentials_async" in stats
        
        if hasattr(debug_client, 'export_debug_info'):
            debug_info = debug_client.export_debug_info()
            assert isinstance(debug_info, dict)
            assert "config" in debug_info
            assert "performance_stats" in debug_info


class TestAuthClientFactory:
    """Test authentication client factory"""
    
    def test_supported_modes(self):
        """Test getting supported modes"""
        from coyote_infra_security import AuthClientFactory
        
        modes = AuthClientFactory.get_supported_modes()
        assert "real" in modes
        assert "mock" in modes
        assert "debug" in modes
    
    def test_invalid_mode(self):
        """Test creating client with invalid mode"""
        config = AuthConfig(
            server_url="https://auth.example.com",
            client_id="test-client",
            client_secret="test-secret"
        )
        
        with pytest.raises(ValueError, match="Unsupported authentication client mode"):
            create_auth_client(config, mode="invalid_mode")


if __name__ == "__main__":
    # Run basic tests without pytest
    print("Running basic security component tests...")
    
    # Test configuration
    config = AuthConfig(
        server_url="https://auth.example.com",
        client_id="test-client",
        client_secret="test-secret",
        auth_mode=AuthMode.CLIENT_CREDENTIALS
    )
    print(f"✓ Config valid: {config.is_valid()}")
    
    # Test mock client
    async def run_basic_test():
        mock_client = create_auth_client(config, mode="mock")
        result = await mock_client.authenticate_client_credentials_async()
        print(f"✓ Mock auth: {result.success}")
        
        connection_ok = await mock_client.test_connection_async()
        print(f"✓ Connection test: {connection_ok}")
    
    asyncio.run(run_basic_test())
    print("Basic tests completed!")
