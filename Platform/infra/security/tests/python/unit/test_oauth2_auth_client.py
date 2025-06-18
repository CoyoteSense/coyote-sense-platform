"""
Unit tests for OAuth2 Authentication Client Python implementation
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from typing import Dict, Any
import pytest
import pytest_asyncio
from dataclasses import asdict

# Import the OAuth2 client implementation
import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'src'))

from python.interfaces.auth_client import (
    AuthClient,
    AuthConfig,
    AuthToken,
    AuthResult,
    TokenStorage,
    Logger
)


class MockOAuth2TokenStorage(OAuth2TokenStorage):
    """Mock implementation of OAuth2TokenStorage for testing"""
    
    def __init__(self):
        self._tokens: Dict[str, OAuth2Token] = {}
    
    async def store_token_async(self, key: str, token: OAuth2Token) -> bool:
        self._tokens[key] = token
        return True
    
    def store_token(self, key: str, token: OAuth2Token) -> bool:
        self._tokens[key] = token
        return True
    
    async def get_token_async(self, key: str) -> Optional[OAuth2Token]:
        return self._tokens.get(key)
    
    def get_token(self, key: str) -> Optional[OAuth2Token]:
        return self._tokens.get(key)
    
    async def delete_token_async(self, key: str) -> bool:
        if key in self._tokens:
            del self._tokens[key]
            return True
        return False
    
    def delete_token(self, key: str) -> bool:
        if key in self._tokens:
            del self._tokens[key]
            return True
        return False
    
    async def clear_async(self) -> None:
        self._tokens.clear()
    
    def clear(self) -> None:
        self._tokens.clear()
    
    def has_token(self, key: str) -> bool:
        """Helper method for testing"""
        return key in self._tokens


class MockOAuth2Logger(OAuth2Logger):
    """Mock implementation of OAuth2Logger for testing"""
    
    def __init__(self):
        self.debug_messages = []
        self.info_messages = []
        self.warning_messages = []
        self.error_messages = []
    
    def debug(self, message: str) -> None:
        self.debug_messages.append(message)
    
    def info(self, message: str) -> None:
        self.info_messages.append(message)
    
    def warning(self, message: str) -> None:
        self.warning_messages.append(message)
    
    def error(self, message: str) -> None:
        self.error_messages.append(message)
    
    def clear_messages(self) -> None:
        """Helper method for testing"""
        self.debug_messages.clear()
        self.info_messages.clear()
        self.warning_messages.clear()
        self.error_messages.clear()


@pytest.fixture
def mock_token_storage():
    """Fixture providing a mock token storage"""
    return MockOAuth2TokenStorage()


@pytest.fixture
def mock_logger():
    """Fixture providing a mock logger"""
    return MockOAuth2Logger()


@pytest.fixture
def oauth2_config():
    """Fixture providing a default OAuth2 configuration"""
    return OAuth2ClientConfig(
        server_url="https://test-auth.example.com",
        client_id="test-client-id",
        client_secret="test-client-secret",
        default_scopes=["read", "write"],
        auto_refresh=False,  # Disable for most tests
        timeout_seconds=30
    )


@pytest.fixture
def oauth2_client(oauth2_config, mock_token_storage, mock_logger):
    """Fixture providing an OAuth2 client with mocked dependencies"""
    return OAuth2AuthClient(oauth2_config, mock_token_storage, mock_logger)


def create_test_token(
    access_token: str = "test-access-token",
    token_type: str = "Bearer",
    expires_in: int = 3600,
    refresh_token: Optional[str] = None,
    scope: str = "read write"
) -> OAuth2Token:
    """Helper function to create test tokens"""
    return OAuth2Token(
        access_token=access_token,
        token_type=token_type,
        expires_in=expires_in,
        refresh_token=refresh_token,
        scope=scope,
        issued_at=datetime.utcnow()
    )


def create_mock_response(
    status_code: int = 200,
    json_data: Dict[str, Any] = None,
    text_data: str = ""
) -> Mock:
    """Helper function to create mock HTTP responses"""
    mock_response = Mock()
    mock_response.status_code = status_code
    mock_response.json.return_value = json_data or {}
    mock_response.text = text_data or json.dumps(json_data or {})
    mock_response.raise_for_status = Mock()
    
    if status_code >= 400:
        mock_response.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
    
    return mock_response


class TestOAuth2AuthClientConfiguration:
    """Tests for OAuth2AuthClient configuration and initialization"""

    def test_constructor_with_valid_config(self, oauth2_config, mock_token_storage, mock_logger):
        """Test OAuth2AuthClient constructor with valid configuration"""
        client = OAuth2AuthClient(oauth2_config, mock_token_storage, mock_logger)
        
        assert client.config.server_url == oauth2_config.server_url
        assert client.config.client_id == oauth2_config.client_id
        assert client.config.client_secret == oauth2_config.client_secret

    def test_constructor_with_invalid_config(self, mock_token_storage, mock_logger):
        """Test OAuth2AuthClient constructor with invalid configuration"""
        invalid_config = OAuth2ClientConfig(
            server_url="",  # Missing required field
            client_id="",   # Missing required field
        )
        
        with pytest.raises(ValueError):
            OAuth2AuthClient(invalid_config, mock_token_storage, mock_logger)

    def test_constructor_with_none_dependencies(self, oauth2_config):
        """Test OAuth2AuthClient constructor with None dependencies"""
        with pytest.raises(ValueError):
            OAuth2AuthClient(oauth2_config, None, None)


class TestOAuth2AuthClientCredentialsFlow:
    """Tests for OAuth2 Client Credentials flow"""

    @pytest.mark.asyncio
    async def test_client_credentials_async_success(self, oauth2_client):
        """Test successful client credentials flow"""
        token_response = {
            "access_token": "test-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read write"
        }
        
        mock_response = create_mock_response(200, token_response)
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await oauth2_client.client_credentials_async(["read", "write"])
        
        assert result.success is True
        assert result.token is not None
        assert result.token.access_token == "test-access-token"
        assert result.token.token_type == "Bearer"
        assert result.token.expires_in == 3600

    @pytest.mark.asyncio
    async def test_client_credentials_async_error(self, oauth2_client):
        """Test client credentials flow with error response"""
        error_response = {
            "error": "invalid_client",
            "error_description": "Authentication failed"
        }
        
        mock_response = create_mock_response(401, error_response)
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await oauth2_client.client_credentials_async(["read", "write"])
        
        assert result.success is False
        assert result.error == "invalid_client"
        assert result.error_description == "Authentication failed"
        assert result.token is None

    def test_client_credentials_sync_success(self, oauth2_client):
        """Test successful client credentials flow (sync)"""
        token_response = {
            "access_token": "test-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read write"
        }
        
        mock_response = create_mock_response(200, token_response)
        
        with patch('requests.post', return_value=mock_response):
            result = oauth2_client.client_credentials(["read", "write"])
        
        assert result.success is True
        assert result.token is not None
        assert result.token.access_token == "test-access-token"

    @pytest.mark.asyncio
    async def test_client_credentials_network_error(self, oauth2_client):
        """Test client credentials flow with network error"""
        with patch('aiohttp.ClientSession.post', side_effect=Exception("Network error")):
            result = await oauth2_client.client_credentials_async(["read", "write"])
        
        assert result.success is False
        assert "Network error" in result.error
        assert result.token is None


class TestOAuth2AuthJwtBearerFlow:
    """Tests for OAuth2 JWT Bearer flow"""

    @pytest.mark.asyncio
    async def test_jwt_bearer_async_success(self, oauth2_client):
        """Test successful JWT Bearer flow"""
        # Configure JWT settings
        oauth2_client.config.jwt_signing_key_path = "test-key.pem"
        oauth2_client.config.jwt_issuer = "test-issuer"
        
        token_response = {
            "access_token": "jwt-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read write"
        }
        
        mock_response = create_mock_response(200, token_response)
        
        with patch('aiohttp.ClientSession.post') as mock_post, \
             patch.object(oauth2_client, '_create_jwt_assertion', return_value="mock-jwt"):
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await oauth2_client.jwt_bearer_async("test-subject", ["read", "write"])
        
        assert result.success is True
        assert result.token is not None
        assert result.token.access_token == "jwt-access-token"

    @pytest.mark.asyncio
    async def test_jwt_bearer_async_missing_config(self, oauth2_client):
        """Test JWT Bearer flow with missing configuration"""
        # Don't set JWT configuration
        
        with pytest.raises(ValueError):
            await oauth2_client.jwt_bearer_async("test-subject", ["read", "write"])

    def test_jwt_bearer_sync_success(self, oauth2_client):
        """Test successful JWT Bearer flow (sync)"""
        oauth2_client.config.jwt_signing_key_path = "test-key.pem"
        oauth2_client.config.jwt_issuer = "test-issuer"
        
        token_response = {
            "access_token": "jwt-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read write"
        }
        
        mock_response = create_mock_response(200, token_response)
        
        with patch('requests.post', return_value=mock_response), \
             patch.object(oauth2_client, '_create_jwt_assertion', return_value="mock-jwt"):
            
            result = oauth2_client.jwt_bearer("test-subject", ["read", "write"])
        
        assert result.success is True
        assert result.token is not None
        assert result.token.access_token == "jwt-access-token"


class TestOAuth2AuthAuthorizationCodeFlow:
    """Tests for OAuth2 Authorization Code flow"""

    @pytest.mark.asyncio
    async def test_authorization_code_async_success(self, oauth2_client):
        """Test successful authorization code flow"""
        token_response = {
            "access_token": "auth-code-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-token-123",
            "scope": "read write"
        }
        
        mock_response = create_mock_response(200, token_response)
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await oauth2_client.authorization_code_async(
                "test-auth-code", "test-verifier", ["read", "write"]
            )
        
        assert result.success is True
        assert result.token is not None
        assert result.token.access_token == "auth-code-token"
        assert result.token.refresh_token == "refresh-token-123"

    @pytest.mark.asyncio
    async def test_authorization_code_async_invalid_code(self, oauth2_client):
        """Test authorization code flow with invalid code"""
        error_response = {
            "error": "invalid_grant",
            "error_description": "Authorization code is invalid"
        }
        
        mock_response = create_mock_response(400, error_response)
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await oauth2_client.authorization_code_async(
                "invalid-code", "test-verifier", ["read", "write"]
            )
        
        assert result.success is False
        assert result.error == "invalid_grant"
        assert result.error_description == "Authorization code is invalid"

    def test_generate_pkce_challenge(self, oauth2_client):
        """Test PKCE challenge generation"""
        verifier, challenge = oauth2_client.generate_pkce_challenge()
        
        assert len(verifier) >= 43  # PKCE requirement
        assert len(challenge) > 0
        assert verifier != challenge

    def test_generate_authorization_url(self, oauth2_client):
        """Test authorization URL generation"""
        url = oauth2_client.generate_authorization_url(
            ["read", "write"], "test-state", "test-challenge"
        )
        
        assert oauth2_client.config.server_url in url
        assert "response_type=code" in url
        assert "client_id=test-client-id" in url
        assert "scope=read+write" in url
        assert "state=test-state" in url
        assert "code_challenge=test-challenge" in url


class TestOAuth2AuthRefreshTokenFlow:
    """Tests for OAuth2 Refresh Token flow"""

    @pytest.mark.asyncio
    async def test_refresh_token_async_success(self, oauth2_client):
        """Test successful refresh token flow"""
        token_response = {
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new-refresh-token",
            "scope": "read write"
        }
        
        mock_response = create_mock_response(200, token_response)
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await oauth2_client.refresh_token_async("existing-refresh-token")
        
        assert result.success is True
        assert result.token is not None
        assert result.token.access_token == "new-access-token"
        assert result.token.refresh_token == "new-refresh-token"

    @pytest.mark.asyncio
    async def test_refresh_token_async_invalid_token(self, oauth2_client):
        """Test refresh token flow with invalid refresh token"""
        error_response = {
            "error": "invalid_grant",
            "error_description": "Refresh token is invalid"
        }
        
        mock_response = create_mock_response(400, error_response)
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await oauth2_client.refresh_token_async("invalid-refresh-token")
        
        assert result.success is False
        assert result.error == "invalid_grant"
        assert result.error_description == "Refresh token is invalid"


class TestOAuth2AuthTokenIntrospection:
    """Tests for OAuth2 Token Introspection"""

    @pytest.mark.asyncio
    async def test_introspect_token_async_active(self, oauth2_client):
        """Test token introspection with active token"""
        introspection_response = {
            "active": True,
            "scope": "read write",
            "client_id": "test-client-id",
            "exp": int(time.time()) + 3600
        }
        
        mock_response = create_mock_response(200, introspection_response)
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await oauth2_client.introspect_token_async("test-access-token")
        
        assert result.success is True
        assert result.active is True
        assert result.scope == "read write"
        assert result.client_id == "test-client-id"

    @pytest.mark.asyncio
    async def test_introspect_token_async_inactive(self, oauth2_client):
        """Test token introspection with inactive token"""
        introspection_response = {
            "active": False
        }
        
        mock_response = create_mock_response(200, introspection_response)
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await oauth2_client.introspect_token_async("inactive-token")
        
        assert result.success is True
        assert result.active is False


class TestOAuth2AuthTokenRevocation:
    """Tests for OAuth2 Token Revocation"""

    @pytest.mark.asyncio
    async def test_revoke_token_async_success(self, oauth2_client, mock_token_storage):
        """Test successful token revocation"""
        mock_response = create_mock_response(200, {})
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await oauth2_client.revoke_token_async("test-access-token")
        
        assert result.success is True

    @pytest.mark.asyncio
    async def test_revoke_token_async_error(self, oauth2_client):
        """Test token revocation with server error"""
        mock_response = create_mock_response(500, {})
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await oauth2_client.revoke_token_async("test-access-token")
        
        assert result.success is False


class TestOAuth2AuthTokenStorage:
    """Tests for OAuth2 Token Storage"""

    @pytest.mark.asyncio
    async def test_store_and_retrieve_token_async(self, oauth2_client, mock_token_storage):
        """Test storing and retrieving tokens asynchronously"""
        token = create_test_token("stored-token")
        
        # Store token
        stored = await oauth2_client.store_token_async("test-key", token)
        assert stored is True
        
        # Retrieve token
        retrieved = await oauth2_client.get_stored_token_async("test-key")
        assert retrieved is not None
        assert retrieved.access_token == "stored-token"

    def test_store_and_retrieve_token_sync(self, oauth2_client, mock_token_storage):
        """Test storing and retrieving tokens synchronously"""
        token = create_test_token("stored-token")
        
        # Store token
        stored = oauth2_client.store_token("test-key", token)
        assert stored is True
        
        # Retrieve token
        retrieved = oauth2_client.get_stored_token("test-key")
        assert retrieved is not None
        assert retrieved.access_token == "stored-token"

    @pytest.mark.asyncio
    async def test_delete_stored_token_async(self, oauth2_client, mock_token_storage):
        """Test deleting stored tokens asynchronously"""
        token = create_test_token("to-be-deleted")
        
        # Store token first
        await oauth2_client.store_token_async("test-key", token)
        assert mock_token_storage.has_token("test-key")
        
        # Delete token
        deleted = await oauth2_client.delete_stored_token_async("test-key")
        assert deleted is True
        assert not mock_token_storage.has_token("test-key")


class TestOAuth2AuthServerDiscovery:
    """Tests for OAuth2 Server Discovery"""

    @pytest.mark.asyncio
    async def test_discover_server_async_success(self, oauth2_client):
        """Test successful server discovery"""
        discovery_response = {
            "issuer": "https://test-auth.example.com",
            "authorization_endpoint": "https://test-auth.example.com/oauth2/authorize",
            "token_endpoint": "https://test-auth.example.com/oauth2/token",
            "introspection_endpoint": "https://test-auth.example.com/oauth2/introspect",
            "revocation_endpoint": "https://test-auth.example.com/oauth2/revoke",
            "grant_types_supported": ["client_credentials", "authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "tls_client_auth"]
        }
        
        mock_response = create_mock_response(200, discovery_response)
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await oauth2_client.discover_server_async()
        
        assert result.success is True
        assert result.server_info is not None
        assert result.server_info.issuer == "https://test-auth.example.com"
        assert result.server_info.token_endpoint == "https://test-auth.example.com/oauth2/token"
        assert result.server_info.supports_client_credentials is True


class TestOAuth2AuthTokenExpiration:
    """Tests for OAuth2 Token Expiration"""

    def test_is_token_expired_with_expired_token(self, oauth2_client):
        """Test token expiration check with expired token"""
        expired_token = create_test_token("expired-token", expires_in=-3600)  # Expired 1 hour ago
        
        result = oauth2_client.is_token_expired(expired_token)
        assert result is True

    def test_is_token_expired_with_valid_token(self, oauth2_client):
        """Test token expiration check with valid token"""
        valid_token = create_test_token("valid-token", expires_in=3600)  # Expires in 1 hour
        
        result = oauth2_client.is_token_expired(valid_token)
        assert result is False

    def test_is_token_near_expiry_with_near_expiry_token(self, oauth2_client):
        """Test token near expiry check"""
        near_expiry_token = create_test_token("near-expiry-token", expires_in=30)  # Expires in 30 seconds
        buffer_seconds = 60  # 1 minute buffer
        
        result = oauth2_client.is_token_near_expiry(near_expiry_token, buffer_seconds)
        assert result is True

    def test_is_token_near_expiry_with_valid_token(self, oauth2_client):
        """Test token near expiry check with valid token"""
        valid_token = create_test_token("valid-token", expires_in=3600)  # Expires in 1 hour
        buffer_seconds = 60  # 1 minute buffer
        
        result = oauth2_client.is_token_near_expiry(valid_token, buffer_seconds)
        assert result is False


class TestOAuth2AuthAutoRefresh:
    """Tests for OAuth2 Auto-Refresh functionality"""

    @pytest.mark.asyncio
    async def test_start_auto_refresh(self, mock_token_storage, mock_logger):
        """Test starting auto-refresh functionality"""
        config = OAuth2ClientConfig(
            server_url="https://test-auth.example.com",
            client_id="test-client-id",
            client_secret="test-client-secret",
            auto_refresh=True,
            refresh_buffer_seconds=60
        )
        
        client = OAuth2AuthClient(config, mock_token_storage, mock_logger)
        
        # Create an expiring token
        expiring_token = create_test_token("expiring-token", expires_in=30, refresh_token="refresh-token")
        await mock_token_storage.store_token_async("test-key", expiring_token)
        
        # Mock the refresh token response
        token_response = {
            "access_token": "refreshed-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new-refresh-token"
        }
        
        mock_response = create_mock_response(200, token_response)
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            
            # Start auto-refresh
            client.start_auto_refresh("test-key")
            
            # Wait a short time for potential refresh
            await asyncio.sleep(0.1)
            
            # Stop auto-refresh
            client.stop_auto_refresh()

    def test_stop_auto_refresh(self, oauth2_client):
        """Test stopping auto-refresh functionality"""
        # Start and then stop auto-refresh
        oauth2_client.start_auto_refresh("test-key")
        oauth2_client.stop_auto_refresh()
        
        # Should not raise any exceptions


class TestOAuth2AuthConcurrency:
    """Tests for OAuth2 concurrent access"""

    @pytest.mark.asyncio
    async def test_concurrent_token_requests(self, oauth2_client):
        """Test handling multiple concurrent token requests"""
        token_response = {
            "access_token": "concurrent-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read write"
        }
        
        mock_response = create_mock_response(200, token_response)
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            
            # Launch multiple concurrent requests
            tasks = []
            for i in range(5):
                task = oauth2_client.client_credentials_async(["read"])
                tasks.append(task)
            
            # Wait for all to complete
            results = await asyncio.gather(*tasks)
            
            # All should succeed
            for result in results:
                assert result.success is True
                assert result.token is not None
                assert result.token.access_token == "concurrent-token"


class TestOAuth2AuthErrorHandling:
    """Tests for OAuth2 error handling and retry logic"""

    @pytest.mark.asyncio
    async def test_retry_on_network_failure(self, oauth2_config, mock_token_storage, mock_logger):
        """Test retry logic on network failures"""
        config = oauth2_config
        config.retry_attempts = 3
        config.retry_delay_seconds = 0.01  # Short delay for testing
        
        client = OAuth2AuthClient(config, mock_token_storage, mock_logger)
        
        # Mock responses: first two fail, third succeeds
        call_count = 0
        def mock_post_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise Exception("Network error")
            else:
                token_response = {
                    "access_token": "retry-success-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }
                return create_mock_response(200, token_response)
        
        with patch('aiohttp.ClientSession.post', side_effect=mock_post_side_effect):
            result = await client.client_credentials_async(["read", "write"])
        
        assert result.success is True
        assert result.token is not None
        assert result.token.access_token == "retry-success-token"
        assert call_count == 3  # Verify retry attempts

    @pytest.mark.asyncio
    async def test_max_retries_exceeded(self, oauth2_config, mock_token_storage, mock_logger):
        """Test behavior when max retries are exceeded"""
        config = oauth2_config
        config.retry_attempts = 2
        config.retry_delay_seconds = 0.01
        
        client = OAuth2AuthClient(config, mock_token_storage, mock_logger)
        
        # All requests fail
        with patch('aiohttp.ClientSession.post', side_effect=Exception("Network error")):
            result = await client.client_credentials_async(["read", "write"])
        
        assert result.success is False
        assert "Network error" in result.error


class TestOAuth2AuthLogging:
    """Tests for OAuth2 logging integration"""

    @pytest.mark.asyncio
    async def test_logging_integration(self, oauth2_client, mock_logger):
        """Test that logging is properly integrated"""
        token_response = {
            "access_token": "logged-token",
            "token_type": "Bearer",
            "expires_in": 3600
        }
        
        mock_response = create_mock_response(200, token_response)
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await oauth2_client.client_credentials_async(["read", "write"])
        
        assert result.success is True
        
        # Verify that info messages were logged
        assert len(mock_logger.info_messages) > 0
        
        # Check that relevant operations were logged
        logged_text = " ".join(mock_logger.info_messages)
        assert "client_credentials" in logged_text.lower()

    def test_error_logging(self, oauth2_client, mock_logger):
        """Test that errors are properly logged"""
        with patch('requests.post', side_effect=Exception("Network error")):
            result = oauth2_client.client_credentials(["read", "write"])
        
        assert result.success is False
        
        # Verify that error messages were logged
        assert len(mock_logger.error_messages) > 0
        
        # Check that the error was logged
        logged_text = " ".join(mock_logger.error_messages)
        assert "error" in logged_text.lower()


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])
