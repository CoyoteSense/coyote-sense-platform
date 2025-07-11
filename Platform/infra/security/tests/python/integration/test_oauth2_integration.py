"""
Integration tests for OAuth2 authentication client against real OAuth2 server
"""

import asyncio
import os
import pytest
import httpx
from typing import Dict, Any, Optional
from unittest.mock import Mock
import sys

# Add src directory to path for imports
security_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
src_path = os.path.join(security_root, 'src', 'python')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from interfaces.auth_client import (
    AuthClient,
    AuthConfig,
    TokenStorage,
    Logger
)
from factory.auth_client_factory import create_auth_client

# Import OAuth2 specific classes
from impl.real.auth_client import OAuth2TokenStorage, OAuth2Logger, OAuth2Token


class MockOAuth2TokenStorage(OAuth2TokenStorage):
    """Mock implementation of token storage for integration tests"""
    
    def __init__(self):
        self._tokens: Dict[str, OAuth2Token] = {}
    
    async def store_token(self, client_id: str, token: OAuth2Token) -> None:
        """Store a token for a client"""
        self._tokens[client_id] = token
    
    def get_token(self, client_id: str) -> Optional[OAuth2Token]:
        """Retrieve a token for a client"""
        return self._tokens.get(client_id)
    
    def clear_token(self, client_id: str) -> None:
        """Clear stored token for a client"""
        self._tokens.pop(client_id, None)
    
    def clear_all_tokens(self) -> None:
        """Clear all stored tokens"""
        self._tokens.clear()


class MockOAuth2Logger(OAuth2Logger):
    """Mock implementation of logger for integration tests"""
    
    def __init__(self):
        self.logs = []
    
    def log_debug(self, message: str) -> None:
        self.logs.append(f"DEBUG: {message}")
    
    def log_info(self, message: str) -> None:
        self.logs.append(f"INFO: {message}")
    
    def log_error(self, message: str) -> None:
        self.logs.append(f"ERROR: {message}")


@pytest.fixture
async def oauth2_config():
    """Configuration for OAuth2 client"""
    from impl.real.auth_client import OAuth2ClientConfig
    return OAuth2ClientConfig(
        server_url=os.getenv("OAUTH2_SERVER_URL", "https://localhost:5001"),
        client_id=os.getenv("OAUTH2_CLIENT_ID", "integration-test-client"),
        client_secret=os.getenv("OAUTH2_CLIENT_SECRET", "integration-test-secret"),
        default_scopes=["api.read", "api.write"],
        auto_refresh=True,
        timeout_seconds=30
    )


@pytest.fixture
async def token_storage():
    """Token storage for tests"""
    return MockOAuth2TokenStorage()


@pytest.fixture
async def logger():
    """Logger for tests"""
    return MockOAuth2Logger()


@pytest.fixture
async def oauth2_client(oauth2_config, token_storage, logger):
    """OAuth2 client for integration tests"""
    from impl.real.auth_client import OAuth2AuthClient
    client = OAuth2AuthClient(oauth2_config, token_storage, logger)
    yield client
    await client.aclose()


@pytest.fixture
async def is_server_available(oauth2_config):
    """Check if OAuth2 server is available for testing"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{oauth2_config.server_url}/.well-known/openid_configuration",
                timeout=5.0
            )
            return response.status_code == 200
    except Exception:
        return False


@pytest.mark.integration
@pytest.mark.asyncio
async def test_client_credentials_flow_success(oauth2_client, is_server_available):
    """Test successful client credentials authentication"""
    if not is_server_available:
        pytest.skip("OAuth2 server is not available")
    
    # Act
    result = await oauth2_client.authenticate_client_credentials(["api.read", "api.write"])
    
    # Assert
    assert result is not None
    assert result.is_success is True
    assert result.token is not None
    assert result.token.access_token is not None
    assert result.token.token_type == "Bearer"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_jwt_bearer_flow_success(oauth2_client, is_server_available):
    """Test successful JWT bearer authentication"""
    if not is_server_available:
        pytest.skip("OAuth2 server is not available")
    
    # Arrange - Get a token to use as JWT
    client_creds_result = await oauth2_client.authenticate_client_credentials()
    assert client_creds_result is not None
    jwt_token = client_creds_result["access_token"]
    
    # Act
    result = await oauth2_client.authenticate_jwt_bearer(jwt_token)
    
    # Assert
    assert result is not None
    assert result.get("access_token") is not None
    assert result.get("token_type") == "Bearer"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_token_introspection_active_token(oauth2_client, is_server_available):
    """Test token introspection with active token"""
    if not is_server_available:
        pytest.skip("OAuth2 server is not available")
    
    # Arrange - Get a valid token
    auth_result = await oauth2_client.authenticate_client_credentials()
    assert auth_result is not None
    access_token = auth_result["access_token"]
    
    # Act
    introspection_result = await oauth2_client.introspect_token(access_token)
    
    # Assert
    assert introspection_result is not None
    assert introspection_result.get("active") is True
    assert introspection_result.get("client_id") == oauth2_client.config.client_id


@pytest.mark.integration
@pytest.mark.asyncio
async def test_token_introspection_inactive_token(oauth2_client, is_server_available):
    """Test token introspection with inactive token"""
    if not is_server_available:
        pytest.skip("OAuth2 server is not available")
    
    # Act
    introspection_result = await oauth2_client.introspect_token("invalid-token")
    
    # Assert
    assert introspection_result is not None
    assert introspection_result.get("active") is False


@pytest.mark.integration
@pytest.mark.asyncio
async def test_token_revocation_success(oauth2_client, is_server_available):
    """Test successful token revocation"""
    if not is_server_available:
        pytest.skip("OAuth2 server is not available")
    
    # Arrange - Get a valid token
    auth_result = await oauth2_client.authenticate_client_credentials()
    assert auth_result is not None
    access_token = auth_result["access_token"]
    
    # Act
    revocation_result = await oauth2_client.revoke_token(access_token)
    
    # Assert
    assert revocation_result is True
    
    # Verify token is no longer active
    introspection_result = await oauth2_client.introspect_token(access_token)
    assert introspection_result.get("active") is False


@pytest.mark.integration
@pytest.mark.asyncio
async def test_server_discovery_endpoints(oauth2_client, is_server_available):
    """Test OAuth2 server discovery"""
    if not is_server_available:
        pytest.skip("OAuth2 server is not available")
    
    # Act
    discovery_result = await oauth2_client.discover_server_endpoints()
    
    # Assert
    assert discovery_result is not None
    assert discovery_result.get("token_endpoint") is not None
    assert discovery_result.get("introspection_endpoint") is not None
    assert discovery_result.get("revocation_endpoint") is not None
    assert "client_credentials" in discovery_result.get("grant_types_supported", [])


@pytest.mark.integration
@pytest.mark.asyncio
async def test_auto_refresh_functionality(oauth2_client, is_server_available, token_storage):
    """Test automatic token refresh functionality"""
    if not is_server_available:
        pytest.skip("OAuth2 server is not available")
    
    # Arrange - Get initial token
    initial_result = await oauth2_client.authenticate_client_credentials()
    assert initial_result is not None
    initial_token = initial_result["access_token"]
    
    # Wait a bit to allow for potential expiration simulation
    await asyncio.sleep(2)
    
    # Act - Request new token (should trigger auto-refresh if needed)
    refreshed_result = await oauth2_client.authenticate_client_credentials()
    
    # Assert
    assert refreshed_result is not None
    assert refreshed_result.get("access_token") is not None
    # Token might be the same if still valid, or different if refreshed


@pytest.mark.integration
@pytest.mark.asyncio
async def test_concurrent_authentication_requests(oauth2_client, is_server_available):
    """Test handling of concurrent authentication requests"""
    if not is_server_available:
        pytest.skip("OAuth2 server is not available")
    
    # Arrange
    num_concurrent_requests = 5
    
    # Act - Create multiple concurrent authentication requests
    tasks = [
        oauth2_client.authenticate_client_credentials()
        for _ in range(num_concurrent_requests)
    ]
    
    results = await asyncio.gather(*tasks)
    
    # Assert
    assert len(results) == num_concurrent_requests
    for result in results:
        assert result is not None
        assert result.get("access_token") is not None
        assert result.get("token_type") == "Bearer"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_invalid_credentials_failure(oauth2_config, is_server_available):
    """Test authentication failure with invalid credentials"""
    if not is_server_available:
        pytest.skip("OAuth2 server is not available")
    
    # Arrange - Create client with invalid credentials
    invalid_config = OAuth2ClientConfiguration(
        server_url=oauth2_config.server_url,
        client_id="invalid-client-id",
        client_secret="invalid-client-secret",
        scope=oauth2_config.scope
    )
    
    invalid_client = OAuth2AuthClient(
        config=invalid_config,
        token_storage=MockOAuth2TokenStorage(),
        logger=MockOAuth2Logger()
    )
    
    try:
        # Act
        with pytest.raises(Exception) as exc_info:
            await invalid_client.authenticate_client_credentials()
        
        # Assert
        assert "invalid_client" in str(exc_info.value).lower() or "unauthorized" in str(exc_info.value).lower()
    
    finally:
        await invalid_client.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_server_health_check(oauth2_client, is_server_available):
    """Test OAuth2 server health check"""
    if not is_server_available:
        pytest.skip("OAuth2 server is not available")
    
    # Act
    health_status = await oauth2_client.check_server_health()
    
    # Assert
    assert health_status is True


@pytest.mark.integration
@pytest.mark.asyncio
async def test_large_scope_authentication(oauth2_client, is_server_available):
    """Test authentication with large scope"""
    if not is_server_available:
        pytest.skip("OAuth2 server is not available")
    
    # Arrange - Create client with large scope
    large_scope_config = OAuth2ClientConfiguration(
        server_url=oauth2_client.config.server_url,
        client_id=oauth2_client.config.client_id,
        client_secret=oauth2_client.config.client_secret,
        scope="api.read api.write api.admin openid profile email",
        enable_auto_refresh=True
    )
    
    large_scope_client = OAuth2AuthClient(
        config=large_scope_config,
        token_storage=MockOAuth2TokenStorage(),
        logger=MockOAuth2Logger()
    )
    
    try:
        # Act
        result = await large_scope_client.authenticate_client_credentials()
        
        # Assert
        assert result is not None
        assert result.get("access_token") is not None
        # The scope in response might be limited by what the server supports
        
    finally:
        await large_scope_client.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_error_handling_network_issues(oauth2_config):
    """Test error handling for network connectivity issues"""
    # Arrange - Create client with unreachable server
    unreachable_config = OAuth2ClientConfiguration(
        server_url="https://unreachable.example.com",
        client_id=oauth2_config.client_id,
        client_secret=oauth2_config.client_secret,
        scope=oauth2_config.scope,
        retry_policy=OAuth2RetryPolicy(max_retries=1, base_delay=0.1)
    )
    
    unreachable_client = OAuth2AuthClient(
        config=unreachable_config,
        token_storage=MockOAuth2TokenStorage(),
        logger=MockOAuth2Logger()
    )
    
    try:
        # Act & Assert
        with pytest.raises(Exception):
            await unreachable_client.authenticate_client_credentials()
    
    finally:
        await unreachable_client.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_timeout_handling(oauth2_config):
    """Test timeout handling for slow responses"""
    # Arrange - Create client with very short timeout
    timeout_config = OAuth2ClientConfiguration(
        server_url=oauth2_config.server_url,
        client_id=oauth2_config.client_id,
        client_secret=oauth2_config.client_secret,
        scope=oauth2_config.scope,
        timeout=0.001  # Very short timeout
    )
    
    timeout_client = OAuth2AuthClient(
        config=timeout_config,
        token_storage=MockOAuth2TokenStorage(),
        logger=MockOAuth2Logger()
    )
    
    try:
        # Act & Assert
        with pytest.raises(Exception):
            await timeout_client.authenticate_client_credentials()
    
    finally:
        await timeout_client.close()


if __name__ == "__main__":
    # Run integration tests
    pytest.main([
        __file__,
        "-v",
        "-m", "integration",
        "--tb=short"
    ])
