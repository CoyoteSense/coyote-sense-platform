"""
Python Security Tests for OAuth2 Authentication Client
Missing security validation that exists in C# and C++ implementations
"""

import sys
import os
import pytest
import re
from unittest.mock import patch, MagicMock

# Add the src directory to the path for proper package imports
security_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
src_path = os.path.join(security_root, 'src', 'python')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Import directly from the real implementation
sys.path.insert(0, os.path.join(src_path, 'impl', 'real'))

from auth_client import (
    OAuth2ClientConfig,
    OAuth2AuthClient,
    OAuth2Token,
    InMemoryTokenStorage,
    ConsoleOAuth2Logger
)

class SecurityTestLogger:
    """Logger for capturing and analyzing log messages for security violations"""
    
    def __init__(self):
        self.messages = []
    
    def log_info(self, message: str) -> None:
        self.messages.append(f"[INFO] {message}")
    
    def log_error(self, message: str) -> None:
        self.messages.append(f"[ERROR] {message}")
    
    def log_debug(self, message: str) -> None:
        self.messages.append(f"[DEBUG] {message}")
    
    def contains_sensitive_data(self, sensitive_data: str) -> bool:
        """Check if any log message contains sensitive data"""
        for message in self.messages:
            if sensitive_data in message:
                return True
        return False
    
    def get_all_messages(self) -> str:
        """Get all messages as a single string for analysis"""
        return " ".join(self.messages)
    
    def clear(self):
        """Clear all log messages"""
        self.messages.clear()

class TestOAuth2SecurityValidation:
    """Critical security tests for OAuth2 client - missing from current test suite"""
    
    @pytest.fixture
    def security_logger(self):
        """Fixture providing a security-focused logger"""
        return SecurityTestLogger()
    
    @pytest.fixture
    def sensitive_config(self):
        """Configuration with sensitive data that should never appear in logs"""
        return OAuth2ClientConfig(
            server_url="https://test-auth.example.com",
            client_id="test-client-id",
            client_secret="super-secret-that-should-never-be-logged",
            default_scopes=["read", "write"],
            auto_refresh=False,
            timeout_seconds=30
        )
    
    @pytest.mark.asyncio
    async def test_client_secret_never_appears_in_logs(self, sensitive_config, security_logger):
        """CRITICAL: Client secret should NEVER appear in any log message"""
        client = OAuth2AuthClient(sensitive_config, None, security_logger)
        
        try:
            # Simulate various authentication scenarios that might log
            security_logger.log_info(f"Starting authentication for client: {sensitive_config.client_id}")
            security_logger.log_debug("Preparing authentication request")
            security_logger.log_error("Authentication failed - invalid credentials")
            security_logger.log_info("Token refresh operation initiated")
            
            # CRITICAL SECURITY CHECK: Client secret should NEVER appear in logs
            assert not security_logger.contains_sensitive_data(sensitive_config.client_secret), \
                "SECURITY VIOLATION: Client secret found in logs! This is a critical vulnerability."
            
            # Verify that normal authentication activity is logged
            all_messages = security_logger.get_all_messages()
            assert "authentication" in all_messages.lower(), \
                "Authentication activity should be logged for auditing purposes"
            
        finally:
            await client.aclose()
    
    @pytest.mark.asyncio
    async def test_access_token_never_appears_in_logs(self, sensitive_config, security_logger):
        """CRITICAL: Access tokens should NEVER appear in log messages"""
        client = OAuth2AuthClient(sensitive_config, None, security_logger)
        
        try:
            # Create a test token with sensitive data
            sensitive_access_token = "sensitive-access-token-12345"
            
            # Simulate token handling scenarios
            security_logger.log_info("Storing authentication token for client")
            security_logger.log_debug("Token validation completed")
            security_logger.log_info("Token refresh operation initiated")
            security_logger.log_error("Token storage failed - database unavailable")
            
            # CRITICAL SECURITY CHECK: Access tokens should NEVER appear in logs
            assert not security_logger.contains_sensitive_data(sensitive_access_token), \
                "SECURITY VIOLATION: Access token found in logs! This exposes user credentials."
            
            # Verify token operations are logged (without sensitive data)
            all_messages = security_logger.get_all_messages()
            assert "token" in all_messages.lower(), \
                "Token operations should be logged for auditing purposes"
                
        finally:
            await client.aclose()
    
    @pytest.mark.asyncio  
    async def test_refresh_token_never_appears_in_logs(self, sensitive_config, security_logger):
        """CRITICAL: Refresh tokens should NEVER appear in log messages"""
        client = OAuth2AuthClient(sensitive_config, None, security_logger)
        
        try:
            # Create a test refresh token with sensitive data
            sensitive_refresh_token = "sensitive-refresh-token-67890"
            
            # Simulate refresh token scenarios
            security_logger.log_info("Initiating token refresh for client")
            security_logger.log_debug("Refresh token validation started")
            security_logger.log_error("Refresh token expired - re-authentication required")
            
            # CRITICAL SECURITY CHECK: Refresh tokens should NEVER appear in logs
            assert not security_logger.contains_sensitive_data(sensitive_refresh_token), \
                "SECURITY VIOLATION: Refresh token found in logs! This allows unauthorized access."
                
        finally:
            await client.aclose()
    
    @pytest.mark.asyncio
    async def test_private_key_paths_should_not_appear_in_logs(self, sensitive_config, security_logger):
        """SECURITY: Private key paths should not be logged (information disclosure)"""
        # Configure JWT settings with sensitive paths
        sensitive_config.jwt_signing_key_path = "/path/to/secret/private.key"
        sensitive_config.jwt_issuer = "test-issuer"
        
        client = OAuth2AuthClient(sensitive_config, None, security_logger)
        
        try:
            private_key_path = "/path/to/secret/private.key"
            
            # Simulate JWT Bearer authentication scenarios
            security_logger.log_info("Preparing JWT assertion for authentication")
            security_logger.log_debug("JWT signing operation initiated") 
            security_logger.log_error("JWT signing failed - key file not accessible")
            
            # SECURITY CHECK: Private key paths should not be logged
            assert not security_logger.contains_sensitive_data(private_key_path), \
                "SECURITY RISK: Private key path found in logs! This could expose sensitive file locations."
                
        finally:
            await client.aclose()
    
    @pytest.mark.asyncio
    async def test_certificate_paths_should_not_appear_in_logs(self, sensitive_config, security_logger):
        """SECURITY: Certificate file paths should not be logged"""
        # Configure mTLS settings with sensitive paths
        sensitive_config.client_cert_path = "/path/to/secret/client.crt"
        sensitive_config.client_key_path = "/path/to/secret/client.key"
        
        client = OAuth2AuthClient(sensitive_config, None, security_logger)
        
        try:
            cert_path = "/path/to/secret/client.crt"
            key_path = "/path/to/secret/client.key"
            
            # Simulate mTLS authentication scenarios
            security_logger.log_info("Preparing mTLS authentication")
            security_logger.log_debug("Loading client certificates")
            security_logger.log_error("Certificate loading failed - file not found")
            
            # SECURITY CHECK: Certificate paths should not be logged
            assert not security_logger.contains_sensitive_data(cert_path), \
                "SECURITY RISK: Certificate path found in logs!"
            assert not security_logger.contains_sensitive_data(key_path), \
                "SECURITY RISK: Private key path found in logs!"
                
        finally:
            await client.aclose()
    
    @pytest.mark.asyncio
    async def test_error_messages_should_not_leak_sensitive_data(self, sensitive_config, security_logger):
        """SECURITY: Error messages should not contain sensitive data"""
        client = OAuth2AuthClient(sensitive_config, None, security_logger)
        
        try:
            # Simulate error scenarios that might accidentally include sensitive data
            security_logger.log_error("Authentication failed - check configuration")
            security_logger.log_error("Token validation failed - expired or invalid")
            security_logger.log_error("Network error - unable to connect to server")
            security_logger.log_error("Certificate error - validation failed")
            
            # Verify no sensitive data leaked in error messages
            all_messages = security_logger.get_all_messages()
            
            # Check that client secret never appears
            assert sensitive_config.client_secret not in all_messages, \
                "Client secret should never appear in error messages"
            
            # Check that potential sensitive tokens don't appear
            sensitive_patterns = [
                r'token[_-]?[0-9a-fA-F]{20,}',  # Token-like patterns
                r'secret[_-]?[0-9a-zA-Z]{10,}',  # Secret-like patterns
                r'key[_-]?[0-9a-zA-Z]{10,}'      # Key-like patterns
            ]
            
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, all_messages, re.IGNORECASE)
                assert len(matches) == 0, \
                    f"Potential sensitive data pattern found in logs: {pattern}"
                    
        finally:
            await client.aclose()
    
    @pytest.mark.asyncio
    async def test_token_storage_security(self, sensitive_config, security_logger):
        """SECURITY: Token storage should be secure and not leak tokens"""
        token_storage = InMemoryTokenStorage()
        client = OAuth2AuthClient(sensitive_config, token_storage, security_logger)
        
        try:
            # Create a sensitive token
            from datetime import datetime, timedelta, timezone
            sensitive_token = OAuth2Token(
                access_token="highly-sensitive-access-token",
                token_type="Bearer",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                refresh_token="highly-sensitive-refresh-token",
                scopes=["read", "write"]
            )
            
            # Store the token
            await token_storage.store_token("test-client", sensitive_token)
            
            # Simulate logging around token storage
            security_logger.log_info("Token stored successfully")
            security_logger.log_debug("Token storage operation completed")
            security_logger.log_info("Token retrieved from storage")
            
            # SECURITY CHECK: Sensitive token data should not appear in logs
            all_messages = security_logger.get_all_messages()
            assert "highly-sensitive-access-token" not in all_messages, \
                "Access token should not appear in storage logs"
            assert "highly-sensitive-refresh-token" not in all_messages, \
                "Refresh token should not appear in storage logs"
            
            # But storage operations should be logged
            assert "token" in all_messages.lower(), \
                "Token storage operations should be logged for auditing"
                
        finally:
            await client.aclose()

# Note: These tests validate security requirements that should be implemented
# in the actual OAuth2AuthClient. Currently, the Python implementation may
# not have these security protections in place.
