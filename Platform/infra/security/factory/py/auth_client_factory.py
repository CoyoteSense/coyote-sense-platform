"""
Authentication Client Factory for Python

This module provides factory methods and builder pattern for creating authentication clients
in the CoyoteSense platform. Supports multiple authentication standards:
- OAuth2 Client Credentials (RFC 6749)
- OAuth2 Authorization Code (RFC 6749) 
- OAuth2 + PKCE (RFC 7636)
- JWT Bearer (RFC 7523)
- mTLS Client Credentials (RFC 8705)
"""

from typing import Optional, List, Dict, Any
from ...interfaces.py.auth_client import (
    AuthMode,
    AuthClientConfig,
    IAuthTokenStorage,
    IAuthLogger,
    IAuthClient
)
from ....http.py.http_client import HttpClient  # Assuming this exists


class AuthClientBuilder:
    """Builder pattern for creating authentication clients with fluent interface."""
    
    def __init__(self):
        self._config_data: Dict[str, Any] = {}
        self._token_storage: Optional[IAuthTokenStorage] = None
        self._logger: Optional[IAuthLogger] = None
    
    def server_url(self, url: str) -> 'AuthClientBuilder':
        """Set authentication server URL."""
        self._config_data['server_url'] = url
        return self
    
    def client_credentials(self, client_id: str, client_secret: Optional[str] = None) -> 'AuthClientBuilder':
        """Set client credentials (ID and secret)."""
        self._config_data['client_id'] = client_id
        if client_secret:
            self._config_data['client_secret'] = client_secret
        return self
    
    def auth_mode(self, mode: AuthMode) -> 'AuthClientBuilder':
        """Set authentication mode."""
        self._config_data['auth_mode'] = mode
        return self
    
    def default_scopes(self, scopes: List[str]) -> 'AuthClientBuilder':
        """Set default scopes."""
        self._config_data['default_scopes'] = scopes
        return self
    
    def mtls_certificates(self, cert_path: str, key_path: str, ca_cert_path: Optional[str] = None) -> 'AuthClientBuilder':
        """Set mTLS certificates for mTLS authentication."""
        self._config_data['client_cert_path'] = cert_path
        self._config_data['client_key_path'] = key_path
        if ca_cert_path:
            self._config_data['ca_cert_path'] = ca_cert_path
        return self
    
    def jwt_settings(self, signing_key_path: str, issuer: str, audience: str, algorithm: str = 'RS256') -> 'AuthClientBuilder':
        """Set JWT settings for JWT Bearer authentication."""
        self._config_data['jwt_signing_key_path'] = signing_key_path
        self._config_data['jwt_issuer'] = issuer
        self._config_data['jwt_audience'] = audience
        self._config_data['jwt_algorithm'] = algorithm
        return self
    
    def redirect_uri(self, uri: str) -> 'AuthClientBuilder':
        """Set redirect URI for Authorization Code flows."""
        self._config_data['redirect_uri'] = uri
        return self
    
    def enable_pkce(self, enable: bool = True) -> 'AuthClientBuilder':
        """Enable PKCE for Authorization Code flow."""
        self._config_data['use_pkce'] = enable
        return self
    
    def timeout(self, timeout_ms: int) -> 'AuthClientBuilder':
        """Set request timeout."""
        self._config_data['timeout_ms'] = timeout_ms
        return self
    
    def custom_headers(self, headers: Dict[str, str]) -> 'AuthClientBuilder':
        """Set custom headers."""
        self._config_data['custom_headers'] = headers
        return self
    
    def auto_refresh(self, enable: bool = True, margin_seconds: int = 300) -> 'AuthClientBuilder':
        """Set automatic token refresh settings."""
        self._config_data['enable_auto_refresh'] = enable
        self._config_data['refresh_margin_seconds'] = margin_seconds
        return self
    
    def token_storage(self, storage: IAuthTokenStorage) -> 'AuthClientBuilder':
        """Set token storage implementation."""
        self._token_storage = storage
        return self
    
    def logger(self, logger: IAuthLogger) -> 'AuthClientBuilder':
        """Set logger implementation."""
        self._logger = logger
        return self
    
    def build(self, http_client: Optional[HttpClient] = None) -> IAuthClient:
        """Build the authentication client."""
        # Validate required fields
        if not self._config_data.get('server_url'):
            raise ValueError('Server URL is required')
        if not self._config_data.get('client_id'):
            raise ValueError('Client ID is required')
        
        # Create configuration
        config = AuthClientConfig(
            auth_mode=self._config_data.get('auth_mode', AuthMode.CLIENT_CREDENTIALS),
            server_url=self._config_data['server_url'],
            client_id=self._config_data['client_id'],
            client_secret=self._config_data.get('client_secret'),
            default_scopes=self._config_data.get('default_scopes', []),
            client_cert_path=self._config_data.get('client_cert_path'),
            client_key_path=self._config_data.get('client_key_path'),
            ca_cert_path=self._config_data.get('ca_cert_path'),
            jwt_signing_key_path=self._config_data.get('jwt_signing_key_path'),
            jwt_algorithm=self._config_data.get('jwt_algorithm'),
            jwt_issuer=self._config_data.get('jwt_issuer'),
            jwt_audience=self._config_data.get('jwt_audience'),
            redirect_uri=self._config_data.get('redirect_uri'),
            use_pkce=self._config_data.get('use_pkce', False),
            timeout_ms=self._config_data.get('timeout_ms', 30000),
            custom_headers=self._config_data.get('custom_headers', {}),
            auto_refresh=self._config_data.get('auto_refresh', True),
            refresh_buffer_seconds=self._config_data.get('refresh_buffer_seconds', 300),
            max_retry_attempts=self._config_data.get('max_retry_attempts', 3),
            retry_delay_ms=self._config_data.get('retry_delay_ms', 1000),
            verify_ssl=self._config_data.get('verify_ssl', True)
        )
        
        # Validate configuration
        if not config.is_valid():
            raise ValueError('Invalid authentication configuration for the selected authentication mode')
        
        # Use provided HTTP client or create a default one
        if not http_client:
            raise ValueError('HTTP client must be provided in build() method')
        
        # Import the actual client implementation
        from ...clients.python.auth_client import AuthClientImpl
        
        return AuthClientImpl(
            config=config,
            http_client=http_client,
            token_storage=self._token_storage,
            logger=self._logger
        )


class AuthClientFactory:
    """Factory class for creating authentication clients with different authentication modes."""
    
    @staticmethod
    def create() -> AuthClientBuilder:
        """Create a new authentication client builder."""
        return AuthClientBuilder()
    
    @staticmethod
    def create_simple(
        server_url: str,
        client_id: str,
        client_secret: Optional[str] = None,
        http_client: Optional[HttpClient] = None
    ) -> IAuthClient:
        """Create authentication client with minimal configuration."""
        return (AuthClientFactory.create()
                .server_url(server_url)
                .client_credentials(client_id, client_secret)
                .build(http_client))
    
    @staticmethod
    def create_client_credentials(
        server_url: str,
        client_id: str,
        client_secret: str,
        scopes: Optional[List[str]] = None,
        http_client: Optional[HttpClient] = None
    ) -> IAuthClient:
        """Create authentication client for Client Credentials flow."""
        builder = (AuthClientFactory.create()
                  .server_url(server_url)
                  .client_credentials(client_id, client_secret)
                  .auth_mode(AuthMode.CLIENT_CREDENTIALS))
        
        if scopes:
            builder.default_scopes(scopes)
        
        return builder.build(http_client)
    
    @staticmethod
    def create_client_credentials_mtls(
        server_url: str,
        client_id: str,
        client_cert_path: str,
        client_key_path: str,
        ca_cert_path: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        http_client: Optional[HttpClient] = None
    ) -> IAuthClient:
        """Create authentication client for Client Credentials with mTLS flow."""
        builder = (AuthClientFactory.create()
                  .server_url(server_url)
                  .client_credentials(client_id)
                  .auth_mode(AuthMode.CLIENT_CREDENTIALS_MTLS)
                  .mtls_certificates(client_cert_path, client_key_path, ca_cert_path))
        
        if scopes:
            builder.default_scopes(scopes)
        
        return builder.build(http_client)
    
    @staticmethod
    def create_jwt_bearer(
        server_url: str,
        client_id: str,
        jwt_signing_key_path: str,
        jwt_issuer: str,
        jwt_audience: str,
        jwt_algorithm: str = 'RS256',
        scopes: Optional[List[str]] = None,
        http_client: Optional[HttpClient] = None
    ) -> IAuthClient:
        """Create authentication client for JWT Bearer flow."""
        builder = (AuthClientFactory.create()
                  .server_url(server_url)
                  .client_credentials(client_id)
                  .auth_mode(AuthMode.JWT_BEARER)
                  .jwt_settings(jwt_signing_key_path, jwt_issuer, jwt_audience, jwt_algorithm))
        
        if scopes:
            builder.default_scopes(scopes)
        
        return builder.build(http_client)
    
    @staticmethod
    def create_authorization_code(
        server_url: str,
        client_id: str,
        redirect_uri: str,
        scopes: Optional[List[str]] = None,
        http_client: Optional[HttpClient] = None
    ) -> IAuthClient:
        """Create authentication client for Authorization Code flow."""
        builder = (AuthClientFactory.create()
                  .server_url(server_url)
                  .client_credentials(client_id)  # No secret for public clients
                  .auth_mode(AuthMode.AUTHORIZATION_CODE)
                  .redirect_uri(redirect_uri))
        
        if scopes:
            builder.default_scopes(scopes)
        
        return builder.build(http_client)
    
    @staticmethod
    def create_authorization_code_pkce(
        server_url: str,
        client_id: str,
        redirect_uri: str,
        scopes: Optional[List[str]] = None,
        http_client: Optional[HttpClient] = None
    ) -> IAuthClient:
        """Create authentication client for Authorization Code with PKCE flow."""
        builder = (AuthClientFactory.create()
                  .server_url(server_url)
                  .client_credentials(client_id)  # No secret for public clients
                  .auth_mode(AuthMode.AUTHORIZATION_CODE_PKCE)
                  .redirect_uri(redirect_uri)
                  .enable_pkce(True))
        
        if scopes:
            builder.default_scopes(scopes)
        
        return builder.build(http_client)


# Legacy aliases for backward compatibility
OAuth2AuthClientBuilder = AuthClientBuilder
OAuth2AuthClientFactory = AuthClientFactory
