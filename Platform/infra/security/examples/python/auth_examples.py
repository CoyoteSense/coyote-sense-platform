"""
Example usage of the CoyoteSense Security Infrastructure Component

This example demonstrates various authentication flows and configurations.
"""

import asyncio
from datetime import datetime

# Import the security component
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python'))

from interfaces import AuthClientConfig, AuthMode
from factory import create_auth_client
from interfaces import ConsoleAuthLogger, InMemoryTokenStorage


async def example_client_credentials():
    """Example: OAuth2 Client Credentials flow"""
    print("=== OAuth2 Client Credentials Example ===")
    
    # Create configuration
    config = AuthClientConfig(
        server_url="https://auth.example.com",
        client_id="trading-client-001",
        client_secret="your-client-secret-here",
        auth_mode=AuthMode.CLIENT_CREDENTIALS,
        default_scopes=["trading", "market-data", "analytics"],
        timeout_ms=30000
    )
    
    # Create client in mock mode for demonstration
    auth_client = create_auth_client(
        config, 
        mode="mock",
        logger=ConsoleAuthLogger("TradingAuth")
    )
    
    # Authenticate
    result = await auth_client.authenticate_client_credentials_async()
    
    if result.success:
        print(f"✓ Authentication successful!")
        print(f"  Token Type: {result.token.token_type}")
        print(f"  Scopes: {', '.join(result.token.scopes)}")
        print(f"  Expires At: {result.token.expires_at}")
        
        # Use the token
        auth_header = result.token.get_authorization_header()
        print(f"  Authorization Header: {auth_header[:20]}...")
        
    else:
        print(f"✗ Authentication failed: {result.error_description}")


async def example_jwt_bearer():
    """Example: JWT Bearer authentication"""
    print("\n=== JWT Bearer Authentication Example ===")
    
    config = AuthClientConfig(
        server_url="https://auth.coyotesense.io",
        client_id="algo-trading-service",
        auth_mode=AuthMode.JWT_BEARER,
        jwt_signing_key_path="/path/to/private-key.pem",
        jwt_issuer="coyotesense-platform",
        jwt_audience="https://api.coyotesense.io",
        default_scopes=["trading", "real-time-data"]
    )
    
    # Create client in mock mode
    auth_client = create_auth_client(config, mode="mock")
    
    # Authenticate with subject
    result = await auth_client.authenticate_jwt_bearer_async(
        subject="algo-trader-001",
        scopes=["trading", "portfolio-management"]
    )
    
    if result.success:
        print(f"✓ JWT Bearer authentication successful!")
        print(f"  Subject: algo-trader-001")
        print(f"  Scopes: {', '.join(result.token.scopes)}")
    else:
        print(f"✗ JWT Bearer authentication failed: {result.error_description}")


async def example_authorization_code():
    """Example: Authorization Code with PKCE flow"""
    print("\n=== Authorization Code + PKCE Example ===")
    
    config = AuthClientConfig(
        server_url="https://auth.coyotesense.io",
        client_id="trader-dashboard",
        auth_mode=AuthMode.AUTHORIZATION_CODE_PKCE,
        redirect_uri="http://localhost:8080/callback",
        default_scopes=["profile", "trading", "analytics"]
    )
    
    auth_client = create_auth_client(config, mode="mock")
    
    # Step 1: Start the authorization flow
    auth_url, code_verifier, state = await auth_client.start_authorization_code_flow_async(
        redirect_uri="http://localhost:8080/callback",
        scopes=["profile", "trading"],
        state="random-state-value"
    )
    
    print(f"✓ Authorization flow started")
    print(f"  Redirect user to: {auth_url}")
    print(f"  State parameter: {state}")
    
    # Step 2: Simulate receiving authorization code from callback
    # In real implementation, this comes from the OAuth2 callback
    if hasattr(auth_client, 'get_mock_authorization_code'):
        mock_auth_code = auth_client.get_mock_authorization_code()
    else:
        mock_auth_code = "mock_auth_code_12345"
    
    # Step 3: Exchange authorization code for tokens
    result = await auth_client.authenticate_authorization_code_async(
        authorization_code=mock_auth_code,
        redirect_uri="http://localhost:8080/callback",
        code_verifier=code_verifier
    )
    
    if result.success:
        print(f"✓ Authorization code exchange successful!")
        print(f"  Access Token: {result.token.access_token[:20]}...")
        print(f"  Refresh Token: {result.token.refresh_token[:20] if result.token.refresh_token else 'None'}...")
        print(f"  ID Token: {result.token.id_token[:20] if result.token.id_token else 'None'}...")
    else:
        print(f"✗ Authorization code exchange failed: {result.error_description}")


async def example_debug_mode():
    """Example: Debug mode with enhanced logging"""
    print("\n=== Debug Mode Example ===")
    
    config = AuthClientConfig(
        server_url="https://auth.example.com",
        client_id="debug-client",
        client_secret="debug-secret",
        auth_mode=AuthMode.CLIENT_CREDENTIALS,
        default_scopes=["debug", "testing"]
    )
    
    # Create client in debug mode
    debug_client = create_auth_client(
        config, 
        mode="debug",
        custom_config={
            "trace_requests": True,
            "trace_responses": True,
            "performance_tracking": True
        }
    )
    
    # Perform authentication
    result = await debug_client.authenticate_client_credentials_async()
    
    if result.success:
        print(f"✓ Debug authentication successful!")
        
        # Check if we have access to debug-specific methods
        if hasattr(debug_client, 'get_performance_stats'):
            stats = debug_client.get_performance_stats()
            print(f"  Performance Stats: {stats}")
        
        if hasattr(debug_client, 'export_debug_info'):
            debug_info = debug_client.export_debug_info()
            print(f"  Debug Info Available: {len(debug_info)} fields")


async def example_token_management():
    """Example: Token management and refresh"""
    print("\n=== Token Management Example ===")
    
    config = AuthClientConfig(
        server_url="https://auth.example.com",
        client_id="trading-bot",
        client_secret="bot-secret",
        auth_mode=AuthMode.CLIENT_CREDENTIALS,
        auto_refresh=True,
        refresh_buffer_seconds=300  # Refresh 5 minutes before expiry
    )
    
    # Use custom token storage
    token_storage = InMemoryTokenStorage()
    auth_client = create_auth_client(
        config, 
        mode="mock",
        token_storage=token_storage
    )
    
    # Initial authentication
    result = await auth_client.authenticate_client_credentials_async()
    print(f"✓ Initial authentication: {result.success}")
    
    # Check current token status
    print(f"  Is Authenticated: {auth_client.is_authenticated}")
    
    # Get valid token (will auto-refresh if needed)
    valid_token = await auth_client.get_valid_token_async()
    if valid_token:
        print(f"  Valid token available: {valid_token.token_type}")
        print(f"  Expires at: {valid_token.expires_at}")
    
    # Manual token refresh (if refresh token is available)
    if valid_token and valid_token.refresh_token:
        refresh_result = await auth_client.refresh_token_async(valid_token.refresh_token)
        print(f"  Manual refresh: {refresh_result.success}")
    
    # Test connection
    connection_ok = await auth_client.test_connection_async()
    print(f"  Connection test: {'✓ OK' if connection_ok else '✗ Failed'}")


async def example_error_handling():
    """Example: Error handling and recovery"""
    print("\n=== Error Handling Example ===")
    
    config = AuthClientConfig(
        server_url="https://auth.example.com",
        client_id="error-test-client",
        client_secret="invalid-secret",  # Intentionally invalid
        auth_mode=AuthMode.CLIENT_CREDENTIALS
    )
    
    # Create mock client configured to simulate failures
    auth_client = create_auth_client(
        config, 
        mode="mock",
        custom_config={
            "should_fail": True,  # Force failures for testing
            "failure_rate": 0.5   # 50% failure rate
        }
    )
    
    # Attempt authentication with error handling
    for attempt in range(3):
        print(f"  Attempt {attempt + 1}:")
        result = await auth_client.authenticate_client_credentials_async()
        
        if result.success:
            print(f"    ✓ Success on attempt {attempt + 1}")
            break
        else:
            print(f"    ✗ Failed: {result.error_code} - {result.error_description}")
            if attempt < 2:
                print(f"    Retrying in 1 second...")
                await asyncio.sleep(1)
    
    # Disable failures for mock client
    if hasattr(auth_client, 'set_should_fail'):
        auth_client.set_should_fail(False)
        print("  Disabled failure simulation")
        
        # Try again
        result = await auth_client.authenticate_client_credentials_async()
        print(f"  Final attempt: {'✓ Success' if result.success else '✗ Failed'}")


async def main():
    """Run all examples"""
    print("CoyoteSense Security Infrastructure Component Examples")
    print("=" * 55)
    
    examples = [
        example_client_credentials,
        example_jwt_bearer,
        example_authorization_code,
        example_debug_mode,
        example_token_management,
        example_error_handling
    ]
    
    for example in examples:
        try:
            await example()
            await asyncio.sleep(0.5)  # Brief pause between examples
        except Exception as e:
            print(f"✗ Example failed: {e}")
    
    print("\n" + "=" * 55)
    print("Examples completed!")


if __name__ == "__main__":
    asyncio.run(main())
