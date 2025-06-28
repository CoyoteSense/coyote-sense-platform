"""
Simple test to check if the OAuth2 client can be created and closed properly
"""
import sys
import os
import asyncio

# Add the src directory to the path for proper package imports
security_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
src_path = os.path.join(security_root, 'src', 'python')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Import directly from the real implementation
sys.path.insert(0, os.path.join(src_path, 'impl', 'real'))

from auth_client import OAuth2ClientConfig, OAuth2AuthClient

async def test_simple_creation():
    """Test simple client creation and cleanup"""
    config = OAuth2ClientConfig(
        server_url="https://test-auth.example.com",
        client_id="test-client-id",
        client_secret="test-client-secret"
    )
    
    client = OAuth2AuthClient(config, None, None)
    print("Client created successfully")
    
    # Test basic functionality
    assert client.config.server_url == config.server_url
    print("Basic assertion passed")
    
    # Cleanup
    await client.aclose()
    print("Client closed successfully")

if __name__ == "__main__":
    asyncio.run(test_simple_creation())
    print("Test completed successfully!")
