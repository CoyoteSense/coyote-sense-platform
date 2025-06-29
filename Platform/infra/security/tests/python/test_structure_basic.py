"""
Simple test for the Security Infrastructure Component structure

This test verifies that the basic structure and imports work correctly
without requiring external dependencies.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python'))

def test_interfaces_import():
    """Test that interfaces can be imported"""
    try:
        from interfaces import (
            AuthMode, AuthConfig, AuthToken, AuthResult,
            TokenStorage, Logger, AuthClient
        )
        print("✓ Interfaces imported successfully")
        assert True  # Test passed
    except Exception as e:
        print(f"✗ Interface import failed: {e}")
        assert False, f"Interface import failed: {e}"

def test_oauth2_classes_import():
    """Test that OAuth2 implementation classes can be imported"""
    try:
        # Import directly from the real implementation
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python', 'impl', 'real'))
        from auth_client import (
            OAuth2ClientConfig, OAuth2Token, OAuth2AuthResult, 
            OAuth2TokenStorage, OAuth2Logger, OAuth2AuthClient
        )
        print("✓ OAuth2 classes imported successfully")
        assert True  # Test passed
    except Exception as e:
        print(f"✗ OAuth2 class import failed: {e}")
        assert False, f"OAuth2 class import failed: {e}"

def test_auth_mode_enum():
    """Test AuthMode enum"""
    try:
        from interfaces import AuthMode
        
        # Test enum values (check what's actually available)
        available_modes = [attr for attr in dir(AuthMode) if not attr.startswith('_')]
        assert len(available_modes) > 0, "AuthMode should have some values"
        
        print(f"✓ AuthMode enum works correctly with modes: {available_modes}")
        assert True  # Test passed
    except Exception as e:
        print(f"✗ AuthMode test failed: {e}")
        assert False, f"AuthMode test failed: {e}"

def test_oauth2_config():
    """Test OAuth2ClientConfig"""
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python', 'impl', 'real'))
        from auth_client import OAuth2ClientConfig
        
        # Create configuration
        config = OAuth2ClientConfig(
            server_url="https://auth.example.com",
            client_id="test-client",
            client_secret="test-secret",
            default_scopes=["read", "write"]
        )
        
        # Test configuration
        assert config.server_url == "https://auth.example.com"
        assert config.client_id == "test-client"
        assert config.client_secret == "test-secret"
        assert config.default_scopes == ["read", "write"]
        
        print("✓ OAuth2ClientConfig works correctly")
        assert True  # Test passed
    except Exception as e:
        print(f"✗ OAuth2ClientConfig test failed: {e}")
        assert False, f"OAuth2ClientConfig test failed: {e}"

def test_oauth2_token():
    """Test OAuth2Token"""
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python', 'impl', 'real'))
        from auth_client import OAuth2Token
        from datetime import datetime, timedelta, timezone
        
        # Create token with timezone-aware datetime
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        token = OAuth2Token(
            access_token="test-token",
            token_type="Bearer",
            expires_at=expires_at,
            scopes=["read", "write"]
        )
        
        # Test token functionality
        assert token.access_token == "test-token"
        assert token.token_type == "Bearer"
        assert not token.is_expired
        assert token.scopes == ["read", "write"]
        
        print("✓ OAuth2Token works correctly")
        assert True  # Test passed
    except Exception as e:
        print(f"✗ OAuth2Token test failed: {e}")
        assert False, f"OAuth2Token test failed: {e}"

def test_oauth2_client_creation():
    """Test OAuth2 client creation (basic instantiation)"""
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python', 'impl', 'real'))
        from auth_client import OAuth2ClientConfig, OAuth2AuthClient
        
        # Test that we can create a basic config
        config = OAuth2ClientConfig(
            server_url="https://auth.example.com",
            client_id="test-client",
            client_secret="test-secret"
        )
        
        # Test basic client creation (without actually calling methods that require network)
        client = OAuth2AuthClient(config, None, None)
        assert client.config == config
        assert client.token_storage is not None
        assert client.logger is not None
        
        print("✓ OAuth2AuthClient basic creation works")
        assert True  # Test passed
    except Exception as e:
        print(f"✗ OAuth2AuthClient test failed: {e}")
        assert False, f"OAuth2AuthClient test failed: {e}"

def main():
    """Run all basic tests"""
    print("Running Security Component Structure Tests")
    print("=" * 50)
    
    tests = [
        test_interfaces_import,
        test_auth_mode_enum,
        test_auth_config,
        test_auth_token,
        test_token_storage,
        test_mock_factory
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Tests completed: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All basic structure tests passed!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1

if __name__ == "__main__":
    exit(main())
