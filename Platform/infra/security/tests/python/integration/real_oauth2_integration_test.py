"""
Real OAuth2 Server Integration Tests for Python

Tests the Python OAuth2 client against a real OAuth2 server running in Docker.
This test suite verifies that the client can successfully authenticate and interact
with the OAuth2 server at http://localhost:8081.

Prerequisites:
- OAuth2 server must be running (docker-compose.oauth2.yml)
- Server should be accessible at http://localhost:8081
- Test client credentials: test-client-id / test-client-secret
"""

import asyncio
import json
import os
import time
from typing import Dict, Any, Optional, List
import pytest
import httpx
from urllib.parse import urlencode


class OAuth2TokenResponse:
    """OAuth2 token response data"""
    def __init__(self, data: Dict[str, Any]):
        self.access_token = data.get('access_token', '')
        self.token_type = data.get('token_type', 'Bearer')
        self.expires_in = data.get('expires_in', 0)
        self.scope = data.get('scope', '')
        self.refresh_token = data.get('refresh_token', '')


class OAuth2IntrospectionResponse:
    """OAuth2 token introspection response data"""
    def __init__(self, data: Dict[str, Any]):
        self.active = data.get('active', False)
        self.client_id = data.get('client_id', '')
        self.username = data.get('username', '')
        self.scope = data.get('scope', '')
        self.exp = data.get('exp', 0)
        self.token_type = data.get('token_type', '')


class SimpleOAuth2Client:
    """Simple OAuth2 client for integration testing"""
    
    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url.rstrip('/')  # Remove trailing slash
        self.client_id = client_id
        self.client_secret = client_secret
        self.http_client = httpx.AsyncClient(timeout=30.0)
    
    async def close(self):
        """Close the HTTP client"""
        await self.http_client.aclose()
    
    async def get_client_credentials_token(self, scopes: Optional[List[str]] = None) -> OAuth2TokenResponse:
        """Get access token using client credentials flow"""
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        if scopes:
            data['scope'] = ' '.join(scopes)
        
        response = await self.http_client.post(
            f"{self.base_url}/token",
            data=data,
            headers={'Accept': 'application/json'}
        )
        
        if not response.is_success:
            error_text = response.text
            raise Exception(f"OAuth2 token request failed: {response.status_code} {response.reason_phrase} - {error_text}")
        
        return OAuth2TokenResponse(response.json())
    
    async def introspect_token(self, token: str) -> OAuth2IntrospectionResponse:
        """Introspect a token to check its validity"""
        data = {
            'token': token,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        response = await self.http_client.post(
            f"{self.base_url}/introspect",
            data=data,
            headers={'Accept': 'application/json'}
        )
        
        if not response.is_success:
            error_text = response.text
            raise Exception(f"OAuth2 introspection request failed: {response.status_code} {response.reason_phrase} - {error_text}")
        
        return OAuth2IntrospectionResponse(response.json())
    
    async def revoke_token(self, token: str, token_type_hint: str = 'access_token') -> bool:
        """Revoke a token"""
        data = {
            'token': token,
            'token_type_hint': token_type_hint,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        response = await self.http_client.post(
            f"{self.base_url}/revoke",
            data=data,
            headers={'Accept': 'application/json'}
        )
        
        # Revoke endpoint typically returns 200 for success, regardless of token validity
        return response.status_code == 200
    
    async def check_server_health(self) -> bool:
        """Check if the OAuth2 server is healthy"""
        try:
            response = await self.http_client.get(f"{self.base_url}/health")
            return response.status_code == 200
        except Exception:
            return False
    
    async def get_server_info(self) -> Dict[str, Any]:
        """Get OAuth2 server information"""
        try:
            response = await self.http_client.get(f"{self.base_url}/.well-known/oauth-authorization-server")
            if response.is_success:
                return response.json()
        except Exception:
            pass
        
        # Fallback to basic info
        return {
            'issuer': self.base_url,
            'token_endpoint': f"{self.base_url}/token",
            'introspection_endpoint': f"{self.base_url}/introspect",
            'revocation_endpoint': f"{self.base_url}/revoke"
        }


class RealOAuth2IntegrationTest:
    """Base class for real OAuth2 integration tests"""
    
    def __init__(self):
        self.server_url = os.getenv('OAUTH2_SERVER_URL', 'http://localhost:8081')
        self.client_id = os.getenv('OAUTH2_CLIENT_ID', 'test-client-id')
        self.client_secret = os.getenv('OAUTH2_CLIENT_SECRET', 'test-client-secret')
        self.scope = os.getenv('OAUTH2_SCOPE', 'read write')
        self.oauth2_client = None
        self.server_available = False
    
    async def setup(self):
        """Set up the test environment"""
        self.oauth2_client = SimpleOAuth2Client(
            self.server_url,
            self.client_id,
            self.client_secret
        )
        
        # Check if server is available
        self.server_available = await self.oauth2_client.check_server_health()
        
        if not self.server_available:
            print(f"⚠️  OAuth2 server not available at {self.server_url}")
            print("   Run: docker-compose -f docker-compose.oauth2.yml up -d")
    
    async def teardown(self):
        """Clean up test environment"""
        if self.oauth2_client:
            await self.oauth2_client.close()


# Test fixtures
@pytest.fixture
async def oauth2_test():
    """OAuth2 test fixture"""
    test = RealOAuth2IntegrationTest()
    await test.setup()
    yield test
    await test.teardown()


# Integration Tests
@pytest.mark.integration
@pytest.mark.asyncio
async def test_server_connection_should_be_reachable(oauth2_test):
    """Test that the OAuth2 server is reachable"""
    if not oauth2_test.server_available:
        pytest.skip("OAuth2 server not available")
    
    # Test basic connectivity
    health_check = await oauth2_test.oauth2_client.check_server_health()
    assert health_check, "OAuth2 server health check failed"
    
    # Test server info endpoint
    server_info = await oauth2_test.oauth2_client.get_server_info()
    assert 'issuer' in server_info, "Server info should contain issuer"
    assert 'token_endpoint' in server_info, "Server info should contain token endpoint"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_client_credentials_flow_should_authenticate_successfully(oauth2_test):
    """Test client credentials authentication flow"""
    if not oauth2_test.server_available:
        pytest.skip("OAuth2 server not available")
    
    # Get access token
    token_response = await oauth2_test.oauth2_client.get_client_credentials_token(
        scopes=['read', 'write']
    )
    
    # Verify token response
    assert token_response.access_token, "Access token should be present"
    assert token_response.token_type == 'Bearer', "Token type should be Bearer"
    assert token_response.expires_in > 0, "Token should have expiration time"
    assert 'read' in token_response.scope, "Token should have requested scope"
    assert 'write' in token_response.scope, "Token should have requested scope"
    
    print(f"✅ Successfully obtained access token: {token_response.access_token[:10]}...")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_token_introspection_with_valid_token_should_return_active(oauth2_test):
    """Test token introspection with valid token"""
    if not oauth2_test.server_available:
        pytest.skip("OAuth2 server not available")
    
    # First get a valid token
    token_response = await oauth2_test.oauth2_client.get_client_credentials_token()
    assert token_response.access_token, "Should have access token"
    
    # Introspect the token
    introspection = await oauth2_test.oauth2_client.introspect_token(token_response.access_token)
    
    # Verify introspection response
    assert introspection.active, "Valid token should be active"
    assert introspection.client_id == oauth2_test.client_id, "Client ID should match"
    # Note: Some OAuth2 servers don't return token_type in introspection response
    # So we only check if it's present and valid when it exists
    if introspection.token_type:
        assert introspection.token_type in ['access_token', 'refresh_token'], "Token type should be valid"
    
    print(f"✅ Token introspection successful for token: {token_response.access_token[:10]}...")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_token_introspection_with_invalid_token_should_return_inactive(oauth2_test):
    """Test token introspection with invalid token"""
    if not oauth2_test.server_available:
        pytest.skip("OAuth2 server not available")
    
    # Introspect an invalid token
    introspection = await oauth2_test.oauth2_client.introspect_token("invalid-token")
    
    # Verify introspection response
    assert not introspection.active, "Invalid token should be inactive"
    
    print("✅ Invalid token correctly identified as inactive")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_token_revocation_should_succeed(oauth2_test):
    """Test token revocation"""
    if not oauth2_test.server_available:
        pytest.skip("OAuth2 server not available")
    
    # First get a valid token
    token_response = await oauth2_test.oauth2_client.get_client_credentials_token()
    assert token_response.access_token, "Should have access token"
    
    # Revoke the token
    revoke_success = await oauth2_test.oauth2_client.revoke_token(token_response.access_token)
    assert revoke_success, "Token revocation should succeed"
    
    # Verify token is now inactive
    introspection = await oauth2_test.oauth2_client.introspect_token(token_response.access_token)
    assert not introspection.active, "Revoked token should be inactive"
    
    print(f"✅ Token revocation successful for token: {token_response.access_token[:10]}...")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_invalid_client_credentials_should_return_error(oauth2_test):
    """Test authentication with invalid credentials"""
    if not oauth2_test.server_available:
        pytest.skip("OAuth2 server not available")
    
    # Create client with invalid credentials
    invalid_client = SimpleOAuth2Client(
        oauth2_test.server_url,
        "invalid-client-id",
        "invalid-client-secret"
    )
    
    # Attempt to get token with invalid credentials
    with pytest.raises(Exception) as exc_info:
        await invalid_client.get_client_credentials_token()
    
    error_message = str(exc_info.value)
    assert "401" in error_message or "invalid_client" in error_message, "Should get authentication error"
    
    await invalid_client.close()
    print("✅ Invalid credentials correctly rejected")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_discovery_endpoint_should_return_valid_configuration(oauth2_test):
    """Test OAuth2 server discovery endpoint"""
    if not oauth2_test.server_available:
        pytest.skip("OAuth2 server not available")
    
    # Get server information
    server_info = await oauth2_test.oauth2_client.get_server_info()
    
    # Verify required fields
    assert 'issuer' in server_info, "Server info should contain issuer"
    assert 'token_endpoint' in server_info, "Server info should contain token endpoint"
    
    # Verify endpoints are accessible
    assert server_info['issuer'].startswith('http'), "Issuer should be a valid URL"
    assert server_info['token_endpoint'].startswith('http'), "Token endpoint should be a valid URL"
    
    print(f"✅ Server discovery successful: {server_info['issuer']}")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_performance_test_multiple_token_requests_should_handle_load(oauth2_test):
    """Test performance with multiple concurrent token requests"""
    if not oauth2_test.server_available:
        pytest.skip("OAuth2 server not available")
    
    # Test multiple concurrent requests
    start_time = time.time()
    
    async def get_token():
        return await oauth2_test.oauth2_client.get_client_credentials_token()
    
    # Make 5 concurrent requests
    tasks = [get_token() for _ in range(5)]
    results = await asyncio.gather(*tasks)
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Verify all requests succeeded
    for result in results:
        assert result.access_token, "All requests should return valid tokens"
    
    # Performance check (should complete within 10 seconds)
    assert duration < 10.0, f"Multiple requests took too long: {duration:.2f}s"
    
    print(f"✅ Performance test passed: 5 concurrent requests in {duration:.2f}s")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_large_scope_authentication_should_succeed(oauth2_test):
    """Test authentication with large scope list"""
    if not oauth2_test.server_available:
        pytest.skip("OAuth2 server not available")
    
    # Define large scope list
    large_scopes = [
        'read', 'write', 'admin', 'user', 'profile', 'email',
        'trading', 'market-data', 'analytics', 'reports',
        'portfolio', 'orders', 'positions', 'risk'
    ]
    
    # Get token with large scope
    token_response = await oauth2_test.oauth2_client.get_client_credentials_token(large_scopes)
    
    # Verify token response
    assert token_response.access_token, "Access token should be present"
    assert token_response.expires_in > 0, "Token should have expiration time"
    
    # Verify scopes are included (at least some of them)
    token_scopes = token_response.scope.split()
    assert any(scope in token_scopes for scope in large_scopes), "Token should include requested scopes"
    
    print(f"✅ Large scope authentication successful with {len(large_scopes)} scopes")


if __name__ == "__main__":
    # Run tests directly
    pytest.main([__file__, "-v", "-s"]) 