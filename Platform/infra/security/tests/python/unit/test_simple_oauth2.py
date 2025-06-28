"""
Simple test to verify OAuth2 implementation works
"""
import sys
import os
from datetime import datetime, timedelta

# Add the auth client path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src', 'python', 'impl', 'real'))

def test_import_oauth2_components():
    """Test that we can import all OAuth2 components"""
    try:
        from auth_client import (
            OAuth2Token,
            OAuth2AuthResult,
            OAuth2TokenStorage,
            OAuth2Logger,
            OAuth2ClientConfig,
            OAuth2AuthClient,
            InMemoryTokenStorage,
            NullOAuth2Logger
        )
        print("✅ All OAuth2 components imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False

def test_oauth2_token_creation():
    """Test OAuth2Token creation and methods"""
    try:
        from auth_client import OAuth2Token
        
        # Create a token
        expires_at = datetime.utcnow() + timedelta(seconds=3600)
        token = OAuth2Token(
            access_token="test-token",
            token_type="Bearer", 
            expires_at=expires_at,
            refresh_token="refresh-token",
            scopes=["read", "write"]
        )
        
        # Test token properties
        assert token.access_token == "test-token"
        assert token.token_type == "Bearer"
        assert not token.is_expired
        assert token.needs_refresh(7200) == False  # Shouldn't need refresh in 2 hours
        assert "Bearer test-token" == token.get_authorization_header()
        
        print("✅ OAuth2Token creation and methods work correctly")
        return True
    except Exception as e:
        print(f"❌ OAuth2Token test failed: {e}")
        return False

def test_oauth2_client_creation():
    """Test OAuth2AuthClient creation"""
    try:
        from auth_client import OAuth2AuthClient, OAuth2ClientConfig, InMemoryTokenStorage, NullOAuth2Logger
        
        # Create config
        config = OAuth2ClientConfig(
            server_url="https://test.example.com",
            client_id="test-client",
            client_secret="test-secret"
        )
        
        # Create client with dependencies
        storage = InMemoryTokenStorage()
        logger = NullOAuth2Logger()
        client = OAuth2AuthClient(config, storage, logger)
        
        # Test basic properties
        assert client.config.server_url == "https://test.example.com"
        assert client.config.client_id == "test-client"
        assert client.current_token is None
        assert client.is_authenticated == False
        
        print("✅ OAuth2AuthClient creation works correctly")
        return True
    except Exception as e:
        print(f"❌ OAuth2AuthClient test failed: {e}")
        return False

def run_all_tests():
    """Run all simple tests"""
    print("Running simple OAuth2 tests...\n")
    
    tests = [
        test_import_oauth2_components,
        test_oauth2_token_creation,
        test_oauth2_client_creation
    ]
    
    results = []
    for test in tests:
        print(f"Running {test.__name__}...")
        result = test()
        results.append(result)
        print()
    
    passed = sum(results)
    total = len(results)
    
    print(f"Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests passed! OAuth2 implementation is working correctly.")
    else:
        print("⚠️  Some tests failed. Check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
