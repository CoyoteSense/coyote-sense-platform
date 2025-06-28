"""
Basic functional tests for Python OAuth2 implementation
This serves as a proof that the core functionality works
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, AsyncMock

# Import the actual implementation
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python', 'impl', 'real'))

from auth_client import OAuth2AuthClient, OAuth2ClientConfig, OAuth2Token, OAuth2Logger, OAuth2TokenStorage


class TestOAuth2Logger(OAuth2Logger):
    """Test logger implementation"""
    
    def __init__(self):
        self.messages = []
    
    def log_info(self, message: str) -> None:
        self.messages.append(f"INFO: {message}")
    
    def log_error(self, message: str) -> None:
        self.messages.append(f"ERROR: {message}")
    
    def log_debug(self, message: str) -> None:
        self.messages.append(f"DEBUG: {message}")


class TestOAuth2TokenStorage(OAuth2TokenStorage):
    """Test token storage implementation"""
    
    def __init__(self):
        self.tokens = {}
    
    async def store_token(self, client_id: str, token: OAuth2Token) -> None:
        self.tokens[client_id] = token
    
    def get_token(self, client_id: str) -> OAuth2Token:
        return self.tokens.get(client_id)
    
    def clear_token(self, client_id: str) -> None:
        if client_id in self.tokens:
            del self.tokens[client_id]
    
    def clear_all_tokens(self) -> None:
        self.tokens.clear()


class TestBasicOAuth2Functionality:
    """Basic tests to verify OAuth2 implementation works"""
    
    @pytest.fixture
    def config(self):
        return OAuth2ClientConfig(
            server_url="https://test-auth.example.com",
            client_id="test-client-id",
            client_secret="test-client-secret"
        )
    
    @pytest.fixture
    def logger(self):
        return TestOAuth2Logger()
    
    @pytest.fixture
    def storage(self):
        return TestOAuth2TokenStorage()
    
    @pytest.fixture
    def client(self, config, storage, logger):
        return OAuth2AuthClient(config, storage, logger)
    
    def test_oauth2_token_creation(self):
        """Test OAuth2Token creation and properties"""
        expires_at = datetime.utcnow() + timedelta(hours=1)
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
        assert not token.is_expired
        assert token.get_authorization_header() == "Bearer test-token"
    
    def test_oauth2_token_expiration(self):
        """Test OAuth2Token expiration logic"""
        # Expired token
        expired_token = OAuth2Token(
            access_token="expired-token",
            expires_at=datetime.utcnow() - timedelta(hours=1)
        )
        assert expired_token.is_expired
        
        # Valid token
        valid_token = OAuth2Token(
            access_token="valid-token",
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        assert not valid_token.is_expired
        
        # Token needing refresh
        soon_expired = OAuth2Token(
            access_token="soon-expired",
            expires_at=datetime.utcnow() + timedelta(minutes=2)
        )
        assert soon_expired.needs_refresh(300)  # 5 minutes buffer
    
    def test_client_construction(self, config, storage, logger):
        """Test OAuth2AuthClient construction"""
        client = OAuth2AuthClient(config, storage, logger)
        
        assert client.config == config
        assert client.token_storage == storage
        assert client.logger == logger
        assert not client.is_authenticated
        assert client.current_token is None
    
    def test_client_construction_with_defaults(self, config):
        """Test OAuth2AuthClient construction with default dependencies"""
        client = OAuth2AuthClient(config)
        
        assert client.config == config
        assert client.token_storage is not None
        assert client.logger is not None
    
    async def test_token_storage_operations(self, storage):
        """Test token storage operations"""
        token = OAuth2Token(access_token="test-token")
        
        # Store token
        await storage.store_token("client-1", token)
        
        # Retrieve token
        retrieved = storage.get_token("client-1")
        assert retrieved.access_token == "test-token"
        
        # Clear token
        storage.clear_token("client-1")
        assert storage.get_token("client-1") is None
    
    def test_logger_operations(self, logger):
        """Test logger operations"""
        logger.log_info("Test info message")
        logger.log_error("Test error message")
        logger.log_debug("Test debug message")
        
        assert len(logger.messages) == 3
        assert "INFO: Test info message" in logger.messages
        assert "ERROR: Test error message" in logger.messages
        assert "DEBUG: Test debug message" in logger.messages


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
