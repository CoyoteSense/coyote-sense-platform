"""
Mock Authentication Client Implementation

This module provides a mock authentication client implementation for testing
that simulates authentication behavior without making actual network calls.
"""

import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
import asyncio
import sys
import os

# Add the parent directories to the path so we can import interfaces
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from interfaces.auth_client import (
    AuthClient, AuthConfig, AuthToken, AuthResult,
    TokenStorage, Logger, AuthMode
)


class MockAuthClient(AuthClient):
    """Mock authentication client implementation for testing."""
    
    def __init__(
        self,
        config: AuthConfig,
        token_storage: Optional[TokenStorage] = None,
        logger: Optional[Logger] = None,
        custom_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the mock authentication client.
        
        Args:
            config: Authentication client configuration
            token_storage: Token storage implementation (uses in-memory if not provided)
            logger: Logger implementation (uses console logger if not provided)
            custom_config: Custom configuration for mock behavior
        """
        self.config = config
        self.token_storage = token_storage or InMemoryTokenStorage()
        self.logger = logger or ConsoleAuthLogger("MockAuthClient")
        
        # Mock-specific configuration
        self.mock_config = custom_config or {}
        self.should_fail = self.mock_config.get("should_fail", False)
        self.failure_rate = self.mock_config.get("failure_rate", 0.0)  # 0.0 to 1.0
        self.response_delay_ms = self.mock_config.get("response_delay_ms", 100)
        self.token_lifetime_seconds = self.mock_config.get("token_lifetime_seconds", 3600)
        
        # Mock server info
        self.mock_server_info = AuthServerInfo(
            authorization_endpoint=f"{config.server_url}/authorize",
            token_endpoint=f"{config.server_url}/token",
            introspection_endpoint=f"{config.server_url}/introspect",
            revocation_endpoint=f"{config.server_url}/revoke",
            grant_types_supported=[
                "client_credentials",
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:jwt-bearer"
            ],
            scopes_supported=["read", "write", "admin", "trading", "analytics"]
        )
        
        self.logger.log_info("Mock authentication client initialized")
    
    async def _simulate_delay(self):
        """Simulate network delay."""
        if self.response_delay_ms > 0:
            await asyncio.sleep(self.response_delay_ms / 1000.0)
    
    def _should_simulate_failure(self) -> bool:
        """Determine if this request should fail based on failure rate."""
        if self.should_fail:
            return True
        
        if self.failure_rate > 0.0:
            return secrets.randbelow(100) < (self.failure_rate * 100)
        
        return False
    
    def _create_mock_token(self, scopes: Optional[List[str]] = None) -> AuthToken:
        """Create a mock authentication token."""
        expires_at = datetime.utcnow() + timedelta(seconds=self.token_lifetime_seconds)
        
        token_scopes = scopes or self.config.default_scopes or ["read"]
        
        return AuthToken(
            access_token=f"mock_access_token_{secrets.token_urlsafe(32)}",
            token_type="Bearer",
            expires_at=expires_at,
            refresh_token=f"mock_refresh_token_{secrets.token_urlsafe(32)}",
            scopes=token_scopes,
            id_token=f"mock_id_token_{secrets.token_urlsafe(32)}" if self.config.is_authorization_code_mode() else None
        )
    
    async def authenticate_client_credentials_async(
        self, scopes: Optional[List[str]] = None
    ) -> AuthResult:
        """Authenticate using Client Credentials flow (mock)."""
        await self._simulate_delay()
        
        if self._should_simulate_failure():
            self.logger.log_error("Mock client credentials authentication failed")
            return AuthResult.error_result(
                "invalid_client",
                "Mock authentication failure",
                "Simulated failure for testing"
            )
        
        self.logger.log_info("Mock client credentials authentication successful")
        token = self._create_mock_token(scopes)
        
        await self.token_storage.store_token_async(self.config.client_id, token)
        return AuthResult.success_result(token)
    
    async def authenticate_jwt_bearer_async(
        self, subject: Optional[str] = None, scopes: Optional[List[str]] = None
    ) -> AuthResult:
        """Authenticate using JWT Bearer flow (mock)."""
        await self._simulate_delay()
        
        if self._should_simulate_failure():
            self.logger.log_error("Mock JWT Bearer authentication failed")
            return AuthResult.error_result(
                "invalid_grant",
                "Mock JWT authentication failure",
                "Simulated failure for testing"
            )
        
        self.logger.log_info(f"Mock JWT Bearer authentication successful (subject: {subject})")
        token = self._create_mock_token(scopes)
        
        await self.token_storage.store_token_async(self.config.client_id, token)
        return AuthResult.success_result(token)
    
    async def authenticate_authorization_code_async(
        self, authorization_code: str, redirect_uri: str, code_verifier: Optional[str] = None
    ) -> AuthResult:
        """Authenticate using Authorization Code flow (mock)."""
        await self._simulate_delay()
        
        # Validate mock authorization code format
        if not authorization_code.startswith("mock_auth_code_"):
            self.logger.log_error("Invalid mock authorization code format")
            return AuthResult.error_result(
                "invalid_grant",
                "Invalid authorization code",
                "Authorization code must start with 'mock_auth_code_'"
            )
        
        if self._should_simulate_failure():
            self.logger.log_error("Mock authorization code authentication failed")
            return AuthResult.error_result(
                "invalid_grant",
                "Mock authorization code failure",
                "Simulated failure for testing"
            )
        
        self.logger.log_info("Mock authorization code authentication successful")
        token = self._create_mock_token()
        
        await self.token_storage.store_token_async(self.config.client_id, token)
        return AuthResult.success_result(token)
    
    async def start_authorization_code_flow_async(
        self, redirect_uri: str, scopes: Optional[List[str]] = None, state: Optional[str] = None
    ) -> Tuple[str, str, str]:
        """Start Authorization Code + PKCE flow (mock)."""
        await self._simulate_delay()
        
        # Generate mock values
        code_verifier = f"mock_code_verifier_{secrets.token_urlsafe(32)}"
        mock_state = state or f"mock_state_{secrets.token_urlsafe(16)}"
        
        # Create mock authorization URL
        authorization_url = (
            f"{self.config.server_url}/authorize?"
            f"response_type=code&"
            f"client_id={self.config.client_id}&"
            f"redirect_uri={redirect_uri}&"
            f"state={mock_state}&"
            f"code_challenge=mock_challenge&"
            f"code_challenge_method=S256"
        )
        
        if scopes:
            authorization_url += f"&scope={'+'.join(scopes)}"
        
        self.logger.log_info("Mock authorization code flow started")
        return authorization_url, code_verifier, mock_state
    
    async def refresh_token_async(self, refresh_token: str) -> AuthResult:
        """Refresh access token using refresh token (mock)."""
        await self._simulate_delay()
        
        # Validate mock refresh token format
        if not refresh_token.startswith("mock_refresh_token_"):
            self.logger.log_error("Invalid mock refresh token format")
            return AuthResult.error_result(
                "invalid_grant",
                "Invalid refresh token",
                "Refresh token must start with 'mock_refresh_token_'"
            )
        
        if self._should_simulate_failure():
            self.logger.log_error("Mock token refresh failed")
            return AuthResult.error_result(
                "invalid_grant",
                "Mock token refresh failure",
                "Simulated failure for testing"
            )
        
        self.logger.log_info("Mock token refresh successful")
        token = self._create_mock_token()
        
        await self.token_storage.store_token_async(self.config.client_id, token)
        return AuthResult.success_result(token)
    
    async def get_valid_token_async(self) -> Optional[AuthToken]:
        """Get current valid token (mock)."""
        current_token = self.token_storage.get_token(self.config.client_id)
        
        if not current_token:
            return None
        
        if current_token.is_expired:
            self.logger.log_info("Mock token is expired, clearing")
            self.token_storage.clear_token(self.config.client_id)
            return None
        
        if (self.config.auto_refresh and 
            current_token.needs_refresh(self.config.refresh_buffer_seconds) and 
            current_token.refresh_token):
            
            self.logger.log_info("Mock token needs refresh, attempting refresh")
            refresh_result = await self.refresh_token_async(current_token.refresh_token)
            
            if refresh_result.success:
                return refresh_result.token
            else:
                self.logger.log_error("Mock token refresh failed")
                self.token_storage.clear_token(self.config.client_id)
                return None
        
        return current_token
    
    async def revoke_token_async(self, token: str, token_type_hint: Optional[str] = None) -> bool:
        """Revoke a token (mock)."""
        await self._simulate_delay()
        
        if self._should_simulate_failure():
            self.logger.log_error("Mock token revocation failed")
            return False
        
        self.logger.log_info("Mock token revoked successfully")
        return True
    
    async def introspect_token_async(self, token: str) -> bool:
        """Introspect a token (mock)."""
        await self._simulate_delay()
        
        # Mock tokens starting with "mock_access_token_" are considered active
        is_active = token.startswith("mock_access_token_") and not self._should_simulate_failure()
        
        self.logger.log_debug(f"Mock token introspection: active={is_active}")
        return is_active
    
    async def test_connection_async(self) -> bool:
        """Test connection to authentication server (mock)."""
        await self._simulate_delay()
        
        if self._should_simulate_failure():
            self.logger.log_error("Mock connection test failed")
            return False
        
        self.logger.log_info("Mock connection test successful")
        return True
    
    async def get_server_info_async(self) -> Optional[AuthServerInfo]:
        """Get authentication server information (mock)."""
        await self._simulate_delay()
        
        if self._should_simulate_failure():
            self.logger.log_error("Mock server info retrieval failed")
            return None
        
        self.logger.log_info("Mock server info retrieved")
        return self.mock_server_info
    
    def clear_tokens(self) -> None:
        """Clear stored tokens."""
        self.token_storage.clear_token(self.config.client_id)
        self.logger.log_info("Mock tokens cleared")
    
    @property
    def current_token(self) -> Optional[AuthToken]:
        """Current token (if any)."""
        return self.token_storage.get_token(self.config.client_id)
    
    @property
    def is_authenticated(self) -> bool:
        """Whether client has valid authentication."""
        token = self.current_token
        return token is not None and not token.is_expired
    
    # Mock-specific methods for testing
    
    def set_should_fail(self, should_fail: bool) -> None:
        """Set whether mock should fail (for testing)."""
        self.should_fail = should_fail
        self.logger.log_debug(f"Mock failure mode set to: {should_fail}")
    
    def set_failure_rate(self, failure_rate: float) -> None:
        """Set failure rate (0.0 to 1.0) for testing."""
        self.failure_rate = max(0.0, min(1.0, failure_rate))
        self.logger.log_debug(f"Mock failure rate set to: {self.failure_rate}")
    
    def set_response_delay(self, delay_ms: int) -> None:
        """Set response delay for testing."""
        self.response_delay_ms = max(0, delay_ms)
        self.logger.log_debug(f"Mock response delay set to: {self.response_delay_ms}ms")
    
    def set_token_lifetime(self, lifetime_seconds: int) -> None:
        """Set token lifetime for testing."""
        self.token_lifetime_seconds = max(1, lifetime_seconds)
        self.logger.log_debug(f"Mock token lifetime set to: {self.token_lifetime_seconds}s")
    
    def get_mock_authorization_code(self) -> str:
        """Get a valid mock authorization code for testing."""
        return f"mock_auth_code_{secrets.token_urlsafe(32)}"
