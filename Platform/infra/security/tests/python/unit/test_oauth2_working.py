"""
Working OAuth2 Authentication Client Python tests with proper cleanup
"""
import asyncio
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import pytest
import pytest_asyncio

# Add the src directory to the path for proper package imports
security_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
src_path = os.path.join(security_root, 'src', 'python')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Import directly from the real implementation
sys.path.insert(0, os.path.join(src_path, 'impl', 'real'))

from auth_client import (
    OAuth2Token,
    OAuth2AuthResult,
    OAuth2TokenStorage,
    OAuth2Logger,
    OAuth2ClientConfig,
    OAuth2AuthClient
)

class MockOAuth2TokenStorage(OAuth2TokenStorage):
    """Minimal mock implementation of OAuth2TokenStorage for testing"""
    
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
    
    def clear_token(self, client_id: str) -> None:
        """Clear stored token for a client"""
        self._tokens.pop(client_id, None)
    
    def clear_all_tokens(self) -> None:
        """Clear all stored tokens"""
        self._tokens.clear()

class MockOAuth2Logger(OAuth2Logger):
    """Minimal mock implementation of OAuth2Logger for testing"""
    
    def __init__(self):
        self.messages = []
    
    def log_debug(self, message: str) -> None:
        self.messages.append(f"DEBUG: {message}")
    
    def log_info(self, message: str) -> None:
        self.messages.append(f"INFO: {message}")
    
    def log_error(self, message: str) -> None:
        self.messages.append(f"ERROR: {message}")

@pytest.fixture
def oauth2_config():
    """Fixture providing a default OAuth2 configuration"""
    return OAuth2ClientConfig(
        server_url="https://test-auth.example.com",
        client_id="test-client-id",
        client_secret="test-client-secret",
        default_scopes=["read", "write"],
        auto_refresh=False,
        timeout_seconds=30
    )

@pytest.fixture
def mock_token_storage():
    """Fixture providing a mock token storage"""
    return MockOAuth2TokenStorage()

@pytest.fixture  
def mock_logger():
    """Fixture providing a mock logger"""
    return MockOAuth2Logger()

class TestOAuth2AuthClientBasic:
    """Basic tests for OAuth2AuthClient without complex mocking"""

    @pytest.mark.asyncio
    async def test_constructor_with_valid_config(self, oauth2_config, mock_token_storage, mock_logger):
        """Test OAuth2AuthClient constructor with valid configuration"""
        client = OAuth2AuthClient(oauth2_config, mock_token_storage, mock_logger)
        
        assert client.config.server_url == oauth2_config.server_url
        assert client.config.client_id == oauth2_config.client_id
        assert client.config.client_secret == oauth2_config.client_secret
        
        # Cleanup
        await client.aclose()

    @pytest.mark.asyncio
    async def test_constructor_with_none_dependencies(self, oauth2_config):
        """Test OAuth2AuthClient constructor with None dependencies"""
        client = OAuth2AuthClient(oauth2_config, None, None)
        assert client.config == oauth2_config
        assert client.token_storage is not None
        assert client.logger is not None
        
        # Cleanup
        await client.aclose()

    @pytest.mark.asyncio
    async def test_token_storage_operations(self, oauth2_config, mock_token_storage, mock_logger):
        """Test basic token storage operations"""
        client = OAuth2AuthClient(oauth2_config, mock_token_storage, mock_logger)
        
        # Create a test token
        expires_at = datetime.utcnow() + timedelta(seconds=3600)
        token = OAuth2Token(
            access_token="test-token",
            token_type="Bearer",
            expires_at=expires_at,
            refresh_token=None,
            scopes=["read", "write"]
        )
        
        # Test storing and retrieving via token storage directly
        stored = await mock_token_storage.store_token_async("test-key", token)
        assert stored is True
        
        retrieved = await mock_token_storage.get_token_async("test-key")
        assert retrieved is not None
        assert retrieved.access_token == "test-token"
        
        # Test deletion
        deleted = await mock_token_storage.delete_token_async("test-key")
        assert deleted is True
        
        # Verify deletion
        retrieved_after_delete = await mock_token_storage.get_token_async("test-key")
        assert retrieved_after_delete is None
        
        # Cleanup
        await client.aclose()

    @pytest.mark.asyncio
    async def test_token_expiration_checks(self, oauth2_config, mock_token_storage, mock_logger):
        """Test token expiration functionality"""
        client = OAuth2AuthClient(oauth2_config, mock_token_storage, mock_logger)
        
        # Test expired token
        expired_token = OAuth2Token(
            access_token="expired-token",
            token_type="Bearer",
            expires_at=datetime.utcnow() - timedelta(seconds=3600),  # Expired 1 hour ago
            refresh_token=None,
            scopes=["read"]
        )
        
        assert expired_token.is_expired is True
        
        # Test valid token
        valid_token = OAuth2Token(
            access_token="valid-token",
            token_type="Bearer",
            expires_at=datetime.utcnow() + timedelta(seconds=3600),  # Expires in 1 hour
            refresh_token=None,
            scopes=["read"]
        )
        
        assert valid_token.is_expired is False
        
        # Test near expiry
        near_expiry_token = OAuth2Token(
            access_token="near-expiry-token",
            token_type="Bearer",
            expires_at=datetime.utcnow() + timedelta(seconds=30),  # Expires in 30 seconds
            refresh_token=None,
            scopes=["read"]
        )
        
        assert near_expiry_token.needs_refresh(60) is True  # 60 second buffer
        assert valid_token.needs_refresh(60) is False
        
        # Cleanup
        await client.aclose()

    @pytest.mark.asyncio  
    async def test_pkce_code_generation(self, oauth2_config, mock_token_storage, mock_logger):
        """Test PKCE code verifier generation"""
        client = OAuth2AuthClient(oauth2_config, mock_token_storage, mock_logger)
        
        verifier = client._generate_code_verifier()
        challenge = client._generate_code_challenge(verifier)
        
        assert len(verifier) >= 43  # PKCE minimum requirement
        assert len(challenge) > 0
        assert verifier != challenge
        
        # Cleanup
        await client.aclose()

    @pytest.mark.asyncio
    async def test_authorization_url_generation(self, oauth2_config, mock_token_storage, mock_logger):
        """Test authorization URL generation"""
        client = OAuth2AuthClient(oauth2_config, mock_token_storage, mock_logger)
        
        url, verifier, state = await client.start_authorization_code_flow(
            "http://localhost:8080/callback", ["read", "write"], "test-state"
        )
        
        assert oauth2_config.server_url in url
        assert "response_type=code" in url
        assert "client_id=test-client-id" in url
        assert "scope=read+write" in url
        assert "state=test-state" in url
        assert "code_challenge=" in url
        assert len(verifier) >= 43  # PKCE requirement
        assert state == "test-state"
        
        # Cleanup
        await client.aclose()

    @pytest.mark.asyncio
    async def test_logging_integration(self, oauth2_config, mock_token_storage, mock_logger):
        """Test basic logging integration"""
        client = OAuth2AuthClient(oauth2_config, mock_token_storage, mock_logger)
        
        # The logger should be integrated
        assert client.logger == mock_logger
        
        # Test logging manually
        client.logger.log_info("Test message")
        assert len(mock_logger.messages) > 0
        assert "INFO: Test message" in mock_logger.messages
        
        # Cleanup
        await client.aclose()
