"""
OAuth2 Authentication Client for CoyoteSense Platform
Python implementation supporting Client Credentials, mTLS, JWT Bearer, and Authorization Code flows
"""

import asyncio
import base64
import hashlib
import json
import secrets
import time
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from threading import Timer
from concurrent.futures import ThreadPoolExecutor
import logging

try:
    import jwt
    import requests
    import aiohttp
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError as e:
    raise ImportError(f"Required dependencies not installed: {e}. Please install: pip install PyJWT requests aiohttp cryptography")


@dataclass
class OAuth2ClientConfig:
    """OAuth2 authentication client configuration"""
    server_url: str
    client_id: str
    client_secret: Optional[str] = None
    default_scopes: List[str] = field(default_factory=list)
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    jwt_signing_key_path: Optional[str] = None
    jwt_issuer: Optional[str] = None
    jwt_audience: Optional[str] = None
    refresh_buffer_seconds: int = 300  # 5 minutes
    auto_refresh: bool = True
    timeout_seconds: int = 30
    verify_ssl: bool = True


@dataclass
class OAuth2Token:
    """OAuth2 token information"""
    access_token: str
    token_type: str = "Bearer"
    expires_at: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(hours=1))
    refresh_token: Optional[str] = None
    scopes: List[str] = field(default_factory=list)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired"""
        return datetime.utcnow() >= self.expires_at

    def needs_refresh(self, buffer_seconds: int = 300) -> bool:
        """Check if token needs refresh (within buffer time)"""
        return datetime.utcnow() + timedelta(seconds=buffer_seconds) >= self.expires_at

    def get_authorization_header(self) -> str:
        """Get authorization header value"""
        return f"{self.token_type} {self.access_token}"


@dataclass
class OAuth2AuthResult:
    """OAuth2 authentication result"""
    is_success: bool
    token: Optional[OAuth2Token] = None
    error_code: Optional[str] = None
    error_description: Optional[str] = None
    error_details: Optional[str] = None

    @classmethod
    def success(cls, token: OAuth2Token) -> 'OAuth2AuthResult':
        """Create success result"""
        return cls(is_success=True, token=token)

    @classmethod
    def error(cls, error_code: str, error_description: Optional[str] = None, error_details: Optional[str] = None) -> 'OAuth2AuthResult':
        """Create error result"""
        return cls(
            is_success=False,
            error_code=error_code,
            error_description=error_description,
            error_details=error_details
        )


@dataclass
class OAuth2ServerInfo:
    """OAuth2 server information"""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    introspection_endpoint: Optional[str] = None
    revocation_endpoint: Optional[str] = None
    grant_types_supported: List[str] = field(default_factory=list)
    scopes_supported: List[str] = field(default_factory=list)


class OAuth2TokenStorage(ABC):
    """OAuth2 token storage interface"""

    @abstractmethod
    async def store_token(self, client_id: str, token: OAuth2Token) -> None:
        """Store a token for a client"""
        pass

    @abstractmethod
    def get_token(self, client_id: str) -> Optional[OAuth2Token]:
        """Retrieve a token for a client"""
        pass

    @abstractmethod
    def clear_token(self, client_id: str) -> None:
        """Clear stored token for a client"""
        pass

    @abstractmethod
    def clear_all_tokens(self) -> None:
        """Clear all stored tokens"""
        pass


class OAuth2Logger(ABC):
    """OAuth2 logger interface"""

    @abstractmethod
    def log_info(self, message: str) -> None:
        """Log information message"""
        pass

    @abstractmethod
    def log_error(self, message: str) -> None:
        """Log error message"""
        pass

    @abstractmethod
    def log_debug(self, message: str) -> None:
        """Log debug message"""
        pass


class InMemoryTokenStorage(OAuth2TokenStorage):
    """In-memory token storage implementation"""

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


class ConsoleOAuth2Logger(OAuth2Logger):
    """Console logger implementation"""

    def __init__(self, prefix: str = "OAuth2"):
        self.prefix = prefix

    def log_info(self, message: str) -> None:
        """Log information message"""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{self.prefix}] INFO: {message}")

    def log_error(self, message: str) -> None:
        """Log error message"""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{self.prefix}] ERROR: {message}")

    def log_debug(self, message: str) -> None:
        """Log debug message"""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] [{self.prefix}] DEBUG: {message}")


class NullOAuth2Logger(OAuth2Logger):
    """Null logger implementation (no logging)"""

    def log_info(self, message: str) -> None:
        pass

    def log_error(self, message: str) -> None:
        pass

    def log_debug(self, message: str) -> None:
        pass


class OAuth2AuthClient:
    """OAuth2 authentication client implementation"""

    def __init__(
        self,
        config: OAuth2ClientConfig,
        token_storage: Optional[OAuth2TokenStorage] = None,
        logger: Optional[OAuth2Logger] = None
    ):
        self.config = config
        self.token_storage = token_storage or InMemoryTokenStorage()
        self.logger = logger or NullOAuth2Logger()
        self._current_token: Optional[OAuth2Token] = None
        self._refresh_timer: Optional[Timer] = None
        self._session: Optional[requests.Session] = None
        self._aio_session: Optional[aiohttp.ClientSession] = None

        # Load stored token
        self._load_stored_token()

        # Setup automatic refresh timer if enabled
        if self.config.auto_refresh:
            self._setup_refresh_timer()

    @property
    def current_token(self) -> Optional[OAuth2Token]:
        """Current token (if any)"""
        return self._current_token

    @property
    def is_authenticated(self) -> bool:
        """Whether client has valid authentication"""
        return self._current_token is not None and not self._current_token.is_expired

    def _get_session(self) -> requests.Session:
        """Get or create requests session"""
        if self._session is None:
            self._session = requests.Session()
            self._session.timeout = self.config.timeout_seconds
            self._session.verify = self.config.verify_ssl
            self._session.headers.update({
                'Accept': 'application/json',
                'User-Agent': 'CoyoteSense-OAuth2-Client-Python/1.0'
            })

            if self.config.client_cert_path and self.config.client_key_path:
                self._session.cert = (self.config.client_cert_path, self.config.client_key_path)

        return self._session

    async def _get_aio_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self._aio_session is None:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            connector = aiohttp.TCPConnector(verify_ssl=self.config.verify_ssl)
            
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'CoyoteSense-OAuth2-Client-Python/1.0'
            }

            self._aio_session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers=headers
            )

        return self._aio_session

    async def authenticate_client_credentials(self, scopes: Optional[List[str]] = None) -> OAuth2AuthResult:
        """Authenticate using Client Credentials flow"""
        try:
            self.logger.log_info("Starting Client Credentials authentication")

            data = {
                'grant_type': 'client_credentials',
                'client_id': self.config.client_id
            }

            if self.config.client_secret:
                data['client_secret'] = self.config.client_secret

            if scopes:
                data['scope'] = ' '.join(scopes)
            elif self.config.default_scopes:
                data['scope'] = ' '.join(self.config.default_scopes)

            result = await self._make_token_request(data)

            if result.is_success:
                self.logger.log_info("Client Credentials authentication successful")
                await self._store_token(result.token)
            else:
                self.logger.log_error(f"Client Credentials authentication failed: {result.error_code} - {result.error_description}")

            return result

        except Exception as e:
            self.logger.log_error(f"Client Credentials authentication error: {str(e)}")
            return OAuth2AuthResult.error("authentication_error", "Authentication failed", str(e))

    async def authenticate_jwt_bearer(self, subject: Optional[str] = None, scopes: Optional[List[str]] = None) -> OAuth2AuthResult:
        """Authenticate using JWT Bearer flow"""
        try:
            self.logger.log_info("Starting JWT Bearer authentication")

            if not self.config.jwt_signing_key_path:
                raise ValueError("JWT signing key path is required for JWT Bearer flow")

            jwt_assertion = self._create_jwt_assertion(subject)

            data = {
                'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion': jwt_assertion
            }

            if scopes:
                data['scope'] = ' '.join(scopes)
            elif self.config.default_scopes:
                data['scope'] = ' '.join(self.config.default_scopes)

            result = await self._make_token_request(data)

            if result.is_success:
                self.logger.log_info("JWT Bearer authentication successful")
                await self._store_token(result.token)
            else:
                self.logger.log_error(f"JWT Bearer authentication failed: {result.error_code} - {result.error_description}")

            return result

        except Exception as e:
            self.logger.log_error(f"JWT Bearer authentication error: {str(e)}")
            return OAuth2AuthResult.error("authentication_error", "Authentication failed", str(e))

    async def authenticate_authorization_code(
        self, 
        authorization_code: str, 
        redirect_uri: str, 
        code_verifier: Optional[str] = None
    ) -> OAuth2AuthResult:
        """Authenticate using Authorization Code flow"""
        try:
            self.logger.log_info("Starting Authorization Code authentication")

            data = {
                'grant_type': 'authorization_code',
                'code': authorization_code,
                'redirect_uri': redirect_uri,
                'client_id': self.config.client_id
            }

            if self.config.client_secret:
                data['client_secret'] = self.config.client_secret

            if code_verifier:
                data['code_verifier'] = code_verifier

            result = await self._make_token_request(data)

            if result.is_success:
                self.logger.log_info("Authorization Code authentication successful")
                await self._store_token(result.token)
            else:
                self.logger.log_error(f"Authorization Code authentication failed: {result.error_code} - {result.error_description}")

            return result

        except Exception as e:
            self.logger.log_error(f"Authorization Code authentication error: {str(e)}")
            return OAuth2AuthResult.error("authentication_error", "Authentication failed", str(e))

    async def start_authorization_code_flow(
        self, 
        redirect_uri: str, 
        scopes: Optional[List[str]] = None, 
        state: Optional[str] = None
    ) -> Tuple[str, str, str]:
        """Start Authorization Code + PKCE flow (returns authorization URL)"""
        self.logger.log_info("Starting Authorization Code + PKCE flow")

        code_verifier = self._generate_code_verifier()
        code_challenge = self._generate_code_challenge(code_verifier)
        actual_state = state or secrets.token_urlsafe(32)

        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': redirect_uri,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'state': actual_state
        }

        if scopes:
            params['scope'] = ' '.join(scopes)
        elif self.config.default_scopes:
            params['scope'] = ' '.join(self.config.default_scopes)

        query_string = urllib.parse.urlencode(params)
        authorization_url = f"{self.config.server_url}/authorize?{query_string}"

        return authorization_url, code_verifier, actual_state

    async def refresh_token(self, refresh_token: str) -> OAuth2AuthResult:
        """Refresh access token using refresh token"""
        try:
            self.logger.log_info("Refreshing token")

            data = {
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': self.config.client_id
            }

            if self.config.client_secret:
                data['client_secret'] = self.config.client_secret

            result = await self._make_token_request(data)

            if result.is_success:
                self.logger.log_info("Token refresh successful")
                await self._store_token(result.token)
            else:
                self.logger.log_error(f"Token refresh failed: {result.error_code} - {result.error_description}")

            return result

        except Exception as e:
            self.logger.log_error(f"Token refresh error: {str(e)}")
            return OAuth2AuthResult.error("refresh_error", "Token refresh failed", str(e))

    async def get_valid_token(self) -> Optional[OAuth2Token]:
        """Get current valid token (automatically refreshes if needed)"""
        if self._current_token is None:
            return None

        if not self._current_token.needs_refresh(self.config.refresh_buffer_seconds):
            return self._current_token

        if self._current_token.refresh_token:
            refresh_result = await self.refresh_token(self._current_token.refresh_token)
            if refresh_result.is_success:
                return refresh_result.token

        return self._current_token if not self._current_token.is_expired else None

    async def revoke_token(self, token: str, token_type_hint: Optional[str] = None) -> bool:
        """Revoke a token"""
        try:
            self.logger.log_info("Revoking token")

            data = {'token': token}
            if token_type_hint:
                data['token_type_hint'] = token_type_hint

            session = await self._get_aio_session()
            async with session.post(
                f"{self.config.server_url}/revoke",
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            ) as response:
                success = response.status < 400
                self.logger.log_info(f"Token revocation {'successful' if success else 'failed'}")
                return success

        except Exception as e:
            self.logger.log_error(f"Token revocation error: {str(e)}")
            return False

    async def introspect_token(self, token: str) -> bool:
        """Introspect a token"""
        try:
            self.logger.log_info("Introspecting token")

            data = {'token': token}

            session = await self._get_aio_session()
            async with session.post(
                f"{self.config.server_url}/introspect",
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            ) as response:
                if response.status >= 400:
                    return False

                result = await response.json()
                active = result.get('active', False)
                
                self.logger.log_info(f"Token introspection result: {'active' if active else 'inactive'}")
                return active

        except Exception as e:
            self.logger.log_error(f"Token introspection error: {str(e)}")
            return False

    async def test_connection(self) -> bool:
        """Test connection to OAuth2 server"""
        try:
            self.logger.log_info("Testing connection to OAuth2 server")
            
            session = await self._get_aio_session()
            async with session.head(self.config.server_url) as response:
                result = response.status < 400
                self.logger.log_info(f"Connection test {'successful' if result else 'failed'}")
                return result

        except Exception as e:
            self.logger.log_error(f"Connection test error: {str(e)}")
            return False

    async def get_server_info(self) -> Optional[OAuth2ServerInfo]:
        """Get OAuth2 server information"""
        try:
            self.logger.log_info("Getting OAuth2 server information")

            session = await self._get_aio_session()
            async with session.get(f"{self.config.server_url}/.well-known/oauth-authorization-server") as response:
                if response.status >= 400:
                    # Fallback - create info from known endpoints
                    return OAuth2ServerInfo(
                        authorization_endpoint=f"{self.config.server_url}/authorize",
                        token_endpoint=f"{self.config.server_url}/token",
                        introspection_endpoint=f"{self.config.server_url}/introspect",
                        revocation_endpoint=f"{self.config.server_url}/revoke",
                        grant_types_supported=["client_credentials", "authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"]
                    )

                data = await response.json()

                return OAuth2ServerInfo(
                    authorization_endpoint=data.get('authorization_endpoint', f"{self.config.server_url}/authorize"),
                    token_endpoint=data.get('token_endpoint', f"{self.config.server_url}/token"),
                    introspection_endpoint=data.get('introspection_endpoint', f"{self.config.server_url}/introspect"),
                    revocation_endpoint=data.get('revocation_endpoint', f"{self.config.server_url}/revoke"),
                    grant_types_supported=data.get('grant_types_supported', ["client_credentials", "authorization_code", "refresh_token"]),
                    scopes_supported=data.get('scopes_supported', [])
                )

        except Exception as e:
            self.logger.log_error(f"Get server info error: {str(e)}")
            return None

    def clear_tokens(self) -> None:
        """Clear stored tokens"""
        self.logger.log_info("Clearing stored tokens")
        self._current_token = None
        self.token_storage.clear_token(self.config.client_id)

    # Synchronous wrapper methods
    def authenticate_client_credentials_sync(self, scopes: Optional[List[str]] = None) -> OAuth2AuthResult:
        """Synchronous wrapper for authenticate_client_credentials"""
        return asyncio.run(self.authenticate_client_credentials(scopes))

    def authenticate_jwt_bearer_sync(self, subject: Optional[str] = None, scopes: Optional[List[str]] = None) -> OAuth2AuthResult:
        """Synchronous wrapper for authenticate_jwt_bearer"""
        return asyncio.run(self.authenticate_jwt_bearer(subject, scopes))

    def authenticate_authorization_code_sync(self, authorization_code: str, redirect_uri: str, code_verifier: Optional[str] = None) -> OAuth2AuthResult:
        """Synchronous wrapper for authenticate_authorization_code"""
        return asyncio.run(self.authenticate_authorization_code(authorization_code, redirect_uri, code_verifier))

    def refresh_token_sync(self, refresh_token: str) -> OAuth2AuthResult:
        """Synchronous wrapper for refresh_token"""
        return asyncio.run(self.refresh_token(refresh_token))

    def get_valid_token_sync(self) -> Optional[OAuth2Token]:
        """Synchronous wrapper for get_valid_token"""
        return asyncio.run(self.get_valid_token())

    def revoke_token_sync(self, token: str, token_type_hint: Optional[str] = None) -> bool:
        """Synchronous wrapper for revoke_token"""
        return asyncio.run(self.revoke_token(token, token_type_hint))

    def introspect_token_sync(self, token: str) -> bool:
        """Synchronous wrapper for introspect_token"""
        return asyncio.run(self.introspect_token(token))

    def test_connection_sync(self) -> bool:
        """Synchronous wrapper for test_connection"""
        return asyncio.run(self.test_connection())

    def get_server_info_sync(self) -> Optional[OAuth2ServerInfo]:
        """Synchronous wrapper for get_server_info"""
        return asyncio.run(self.get_server_info())

    async def _make_token_request(self, data: Dict[str, str]) -> OAuth2AuthResult:
        """Make token request to OAuth2 server"""
        session = await self._get_aio_session()
        
        async with session.post(
            f"{self.config.server_url}/token",
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        ) as response:
            response_text = await response.text()

            if response.status >= 400:
                try:
                    error_data = json.loads(response_text)
                    error = error_data.get('error', 'unknown_error')
                    error_description = error_data.get('error_description')
                    return OAuth2AuthResult.error(error, error_description, f"HTTP {response.status}")
                except:
                    return OAuth2AuthResult.error("http_error", f"HTTP {response.status}", response_text)

            try:
                token_data = json.loads(response_text)

                access_token = token_data['access_token']
                token_type = token_data.get('token_type', 'Bearer')
                expires_in = token_data.get('expires_in', 3600)
                refresh_token = token_data.get('refresh_token')
                scope = token_data.get('scope', '')

                token = OAuth2Token(
                    access_token=access_token,
                    token_type=token_type,
                    expires_at=datetime.utcnow() + timedelta(seconds=expires_in),
                    refresh_token=refresh_token,
                    scopes=scope.split() if scope else []
                )

                return OAuth2AuthResult.success(token)

            except Exception as e:
                return OAuth2AuthResult.error("parse_error", "Failed to parse token response", str(e))

    def _create_jwt_assertion(self, subject: Optional[str] = None) -> str:
        """Create JWT assertion for JWT Bearer flow"""
        if not all([self.config.jwt_signing_key_path, self.config.jwt_issuer, self.config.jwt_audience]):
            raise ValueError("JWT configuration is incomplete")

        with open(self.config.jwt_signing_key_path, 'r') as f:
            private_key = f.read()

        now = datetime.utcnow()
        payload = {
            'iss': self.config.jwt_issuer,
            'aud': self.config.jwt_audience,
            'iat': now,
            'exp': now + timedelta(minutes=5),
            'jti': secrets.token_urlsafe(16)
        }

        if subject:
            payload['sub'] = subject

        return jwt.encode(payload, private_key, algorithm='RS256')

    @staticmethod
    def _generate_code_verifier() -> str:
        """Generate code verifier for PKCE"""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

    @staticmethod
    def _generate_code_challenge(code_verifier: str) -> str:
        """Generate code challenge for PKCE"""
        digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

    def _load_stored_token(self) -> None:
        """Load stored token"""
        try:
            self._current_token = self.token_storage.get_token(self.config.client_id)
            if self._current_token:
                self.logger.log_info("Loaded stored token")
        except Exception as e:
            self.logger.log_error(f"Failed to load stored token: {str(e)}")

    async def _store_token(self, token: OAuth2Token) -> None:
        """Store token"""
        self._current_token = token
        try:
            await self.token_storage.store_token(self.config.client_id, token)
        except Exception as e:
            self.logger.log_error(f"Failed to store token: {str(e)}")

    def _setup_refresh_timer(self) -> None:
        """Setup automatic refresh timer"""
        def check_refresh():
            if self._current_token and self._current_token.refresh_token:
                if self._current_token.needs_refresh(self.config.refresh_buffer_seconds):
                    asyncio.create_task(self.refresh_token(self._current_token.refresh_token))
            
            # Schedule next check
            self._refresh_timer = Timer(60.0, check_refresh)  # Check every minute
            self._refresh_timer.start()

        self._refresh_timer = Timer(60.0, check_refresh)
        self._refresh_timer.start()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclose()

    def close(self) -> None:
        """Close synchronous resources"""
        if self._refresh_timer:
            self._refresh_timer.cancel()
        if self._session:
            self._session.close()

    async def aclose(self) -> None:
        """Close asynchronous resources"""
        if self._refresh_timer:
            self._refresh_timer.cancel()
        if self._aio_session:
            await self._aio_session.close()
        if self._session:
            self._session.close()
