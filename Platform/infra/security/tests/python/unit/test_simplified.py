"""
Simplified OAuth2 test file to diagnose pytest hanging issues
"""
import sys
import os
import pytest
import pytest_asyncio

# Add the src directory to the path for proper package imports
security_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
src_path = os.path.join(security_root, 'src', 'python')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Import directly from the real implementation
sys.path.insert(0, os.path.join(src_path, 'impl', 'real'))

from auth_client import OAuth2ClientConfig, OAuth2AuthClient

@pytest.fixture
def oauth2_config():
    """Simple config fixture"""
    return OAuth2ClientConfig(
        server_url="https://test-auth.example.com",
        client_id="test-client-id",
        client_secret="test-client-secret"
    )

class TestSimple:
    """Simple test class"""
    
    @pytest.mark.asyncio
    async def test_simple_constructor(self, oauth2_config):
        """Test simple constructor"""
        client = OAuth2AuthClient(oauth2_config, None, None)
        assert client.config.server_url == oauth2_config.server_url
        await client.aclose()
    
    def test_sync_constructor(self, oauth2_config):
        """Test sync constructor without client usage"""
        config = oauth2_config
        assert config.server_url == "https://test-auth.example.com"
