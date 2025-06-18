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
            AuthMode, AuthClientConfig, AuthToken, AuthResult,
            InMemoryTokenStorage, ConsoleAuthLogger, NullAuthLogger
        )
        print("✓ Interfaces imported successfully")
        return True
    except Exception as e:
        print(f"✗ Interface import failed: {e}")
        return False

def test_auth_mode_enum():
    """Test AuthMode enum"""
    try:
        from interfaces import AuthMode
        
        # Test enum values
        assert AuthMode.CLIENT_CREDENTIALS.value == "client_credentials"
        assert AuthMode.JWT_BEARER.value == "jwt_bearer"
        assert AuthMode.AUTHORIZATION_CODE.value == "authorization_code"
        
        print("✓ AuthMode enum works correctly")
        return True
    except Exception as e:
        print(f"✗ AuthMode test failed: {e}")
        return False

def test_auth_config():
    """Test AuthClientConfig"""
    try:
        from interfaces import AuthClientConfig, AuthMode
        
        # Create configuration
        config = AuthClientConfig(
            server_url="https://auth.example.com",
            client_id="test-client",
            client_secret="test-secret",
            auth_mode=AuthMode.CLIENT_CREDENTIALS
        )
        
        # Test configuration validation
        assert config.is_valid()
        assert config.is_client_credentials_mode()
        assert not config.is_jwt_bearer_mode()
        assert config.requires_client_secret()
        
        print("✓ AuthClientConfig works correctly")
        return True
    except Exception as e:
        print(f"✗ AuthClientConfig test failed: {e}")
        return False

def test_auth_token():
    """Test AuthToken"""
    try:
        from interfaces import AuthToken
        from datetime import datetime, timedelta
        
        # Create token
        expires_at = datetime.utcnow() + timedelta(hours=1)
        token = AuthToken(
            access_token="test-token",
            token_type="Bearer",
            expires_at=expires_at,
            scopes=["read", "write"]
        )
        
        # Test token functionality
        assert token.access_token == "test-token"
        assert not token.is_expired
        assert token.get_authorization_header() == "Bearer test-token"
        
        print("✓ AuthToken works correctly")
        return True
    except Exception as e:
        print(f"✗ AuthToken test failed: {e}")
        return False

def test_token_storage():
    """Test token storage"""
    try:
        from interfaces import InMemoryTokenStorage, AuthToken
        import asyncio
        
        storage = InMemoryTokenStorage()
        token = AuthToken(access_token="test-token")
        client_id = "test-client"
        
        # Test storage operations
        asyncio.run(storage.store_token_async(client_id, token))
        retrieved_token = storage.get_token(client_id)
        
        assert retrieved_token is not None
        assert retrieved_token.access_token == "test-token"
        
        storage.clear_token(client_id)
        assert storage.get_token(client_id) is None
        
        print("✓ Token storage works correctly")
        return True
    except Exception as e:
        print(f"✗ Token storage test failed: {e}")
        return False

def test_mock_factory():
    """Test mock client factory (without external dependencies)"""
    try:
        from interfaces import AuthClientConfig, AuthMode
        
        # Test that we can create a basic config
        config = AuthClientConfig(
            server_url="https://auth.example.com",
            client_id="test-client",
            client_secret="test-secret",
            auth_mode=AuthMode.CLIENT_CREDENTIALS
        )
        
        # Note: We can't actually create the mock client here because it requires
        # the factory which imports implementations that have external dependencies
        # But we can verify the config works
        assert config.is_valid()
        
        print("✓ Mock factory prerequisites work")
        return True
    except Exception as e:
        print(f"✗ Mock factory test failed: {e}")
        return False

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
