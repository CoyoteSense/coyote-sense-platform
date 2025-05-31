/**
 * Multi-Standard Authentication Interfaces and Types for JavaScript
 * 
 * This module contains all the interface definitions and types for multi-standard authentication
 * in the CoyoteSense platform, supporting OAuth2 (RFC 6749), JWT Bearer (RFC 7523), 
 * and mTLS (RFC 8705) authentication methods.
 */

// Authentication Modes

/**
 * Authentication modes supported by the platform
 * @readonly
 * @enum {string}
 */
const AuthMode = {
  /** Standard OAuth2 client credentials flow (RFC 6749) */
  CLIENT_CREDENTIALS: 'client_credentials',
  
  /** Client credentials with mutual TLS authentication (RFC 8705) */
  CLIENT_CREDENTIALS_MTLS: 'client_credentials_mtls',
  
  /** JWT Bearer assertion flow (RFC 7523) */
  JWT_BEARER: 'jwt_bearer',
  
  /** Authorization code flow (RFC 6749) */
  AUTHORIZATION_CODE: 'authorization_code',
  
  /** Authorization code flow with PKCE (RFC 7636) */
  AUTHORIZATION_CODE_PKCE: 'authorization_code_pkce'
};

/**
 * Authentication client configuration
 * @typedef {Object} AuthClientConfig
 * @property {string} [authMode=AuthMode.CLIENT_CREDENTIALS] - Authentication mode to use
 * @property {string} serverUrl - Authentication server base URL
 * @property {string} clientId - Client ID for authentication
 * @property {string} [clientSecret] - Client secret for authentication
 * @property {string[]} [defaultScopes] - Default scopes to request
 * 
 * // mTLS settings
 * @property {string} [clientCertPath] - Client certificate path for mTLS authentication
 * @property {string} [clientKeyPath] - Client certificate key path for mTLS authentication
 * @property {string} [caCertPath] - CA certificate path for mTLS authentication
 * 
 * // JWT Bearer settings
 * @property {string} [jwtSigningKeyPath] - JWT signing key path for JWT Bearer flow
 * @property {string} [jwtAlgorithm='RS256'] - JWT algorithm for JWT Bearer flow
 * @property {string} [jwtIssuer] - JWT issuer for JWT Bearer flow
 * @property {string} [jwtAudience] - JWT audience for JWT Bearer flow
 * 
 * // Authorization Code settings
 * @property {string} [redirectUri] - Redirect URI for authorization code flows
 * @property {boolean} [usePkce=true] - Use PKCE for authorization code flow
 * 
 * @property {number} [refreshBufferSeconds=300] - Token refresh buffer in seconds (refresh before expiry)
 * @property {boolean} [autoRefresh=true] - Enable automatic token refresh
 * @property {number} [maxRetryAttempts=3] - Maximum retry attempts for token operations
 * @property {number} [retryDelayMs=1000] - Retry delay in milliseconds
 * 
 * @property {number} [timeoutMs=30000] - Default timeout for authentication requests in milliseconds
 * @property {boolean} [verifySsl=true] - Verify SSL certificates
 * @property {Object.<string, string>} [customHeaders] - Custom headers to include in authentication requests
 */

/**
 * Authentication token information
 * @typedef {Object} AuthToken
 * @property {string} accessToken - Access token value
 * @property {string} tokenType - Token type (typically 'Bearer')
 * @property {number} expiresAt - Token expiration time as Unix timestamp
 * @property {string} [refreshToken] - Refresh token (if available)
 * @property {string[]} [scopes] - Token scopes
 * @property {string} [idToken] - ID token (for OpenID Connect)
 */

/**
 * Authentication result
 * @typedef {Object} AuthResult
 * @property {boolean} success - Whether the authentication was successful
 * @property {AuthToken} [token] - Access token (if successful)
 * @property {string} [errorCode] - Error code (if failed)
 * @property {string} [errorDescription] - Error description (if failed)
 * @property {string} [errorDetails] - Additional error details (if failed)
 */

/**
 * Authentication server information
 * @typedef {Object} AuthServerInfo
 * @property {string} authorizationEndpoint - Authorization endpoint URL
 * @property {string} tokenEndpoint - Token endpoint URL
 * @property {string} [introspectionEndpoint] - Token introspection endpoint URL
 * @property {string} [revocationEndpoint] - Token revocation endpoint URL
 * @property {string[]} grantTypesSupported - Supported grant types
 * @property {string[]} scopesSupported - Supported scopes
 */

/**
 * Authentication client configuration helper functions
 */
class AuthConfigHelper {
  /**
   * Check if using client credentials mode
   * @param {AuthClientConfig} config - Configuration to check
   * @returns {boolean}
   */
  static isClientCredentialsMode(config) {
    return config.authMode === AuthMode.CLIENT_CREDENTIALS;
  }

  /**
   * Check if using mTLS mode
   * @param {AuthClientConfig} config - Configuration to check
   * @returns {boolean}
   */
  static isMtlsMode(config) {
    return config.authMode === AuthMode.CLIENT_CREDENTIALS_MTLS;
  }

  /**
   * Check if using JWT Bearer mode
   * @param {AuthClientConfig} config - Configuration to check
   * @returns {boolean}
   */
  static isJwtBearerMode(config) {
    return config.authMode === AuthMode.JWT_BEARER;
  }

  /**
   * Check if using any authorization code mode
   * @param {AuthClientConfig} config - Configuration to check
   * @returns {boolean}
   */
  static isAuthorizationCodeMode(config) {
    return config.authMode === AuthMode.AUTHORIZATION_CODE || 
           config.authMode === AuthMode.AUTHORIZATION_CODE_PKCE;
  }

  /**
   * Check if certificates are required for this mode
   * @param {AuthClientConfig} config - Configuration to check
   * @returns {boolean}
   */
  static requiresCertificates(config) {
    return this.isMtlsMode(config);
  }

  /**
   * Check if client secret is required for this mode
   * @param {AuthClientConfig} config - Configuration to check
   * @returns {boolean}
   */
  static requiresClientSecret(config) {
    return this.isClientCredentialsMode(config) || this.isMtlsMode(config);
  }

  /**
   * Check if JWT key is required for this mode
   * @param {AuthClientConfig} config - Configuration to check
   * @returns {boolean}
   */
  static requiresJwtKey(config) {
    return this.isJwtBearerMode(config);
  }

  /**
   * Check if redirect URI is required for this mode
   * @param {AuthClientConfig} config - Configuration to check
   * @returns {boolean}
   */
  static requiresRedirectUri(config) {
    return this.isAuthorizationCodeMode(config);
  }

  /**
   * Validate configuration for the selected authentication mode
   * @param {AuthClientConfig} config - Configuration to validate
   * @returns {boolean}
   */
  static isValid(config) {
    if (!config.clientId || !config.serverUrl) {
      return false;
    }

    switch (config.authMode) {
      case AuthMode.CLIENT_CREDENTIALS:
        return !!config.clientSecret;
      
      case AuthMode.CLIENT_CREDENTIALS_MTLS:
        return !!config.clientSecret && !!config.clientCertPath && !!config.clientKeyPath;
      
      case AuthMode.JWT_BEARER:
        return !!config.jwtSigningKeyPath;
      
      case AuthMode.AUTHORIZATION_CODE:
      case AuthMode.AUTHORIZATION_CODE_PKCE:
        return !!config.redirectUri;
      
      default:
        return false;
    }
  }
}

/**
 * Authentication token storage interface
 */
class IAuthTokenStorage {
  /**
   * Store a token for a client
   * @param {string} clientId - Client ID
   * @param {AuthToken} token - Token to store
   * @returns {Promise<void>}
   */
  async storeTokenAsync(clientId, token) {
    throw new Error('Method must be implemented');
  }

  /**
   * Retrieve a token for a client
   * @param {string} clientId - Client ID
   * @returns {AuthToken|null}
   */
  getToken(clientId) {
    throw new Error('Method must be implemented');
  }

  /**
   * Clear stored token for a client
   * @param {string} clientId - Client ID
   */
  clearToken(clientId) {
    throw new Error('Method must be implemented');
  }

  /**
   * Clear all stored tokens
   */
  clearAllTokens() {
    throw new Error('Method must be implemented');
  }
}

/**
 * Authentication logger interface
 */
class IAuthLogger {
  /**
   * Log information message
   * @param {string} message - Message to log
   */
  logInfo(message) {
    throw new Error('Method must be implemented');
  }

  /**
   * Log error message
   * @param {string} message - Message to log
   */
  logError(message) {
    throw new Error('Method must be implemented');
  }

  /**
   * Log debug message
   * @param {string} message - Message to log
   */
  logDebug(message) {
    throw new Error('Method must be implemented');
  }
}

/**
 * Multi-standard authentication client interface supporting OAuth2 (RFC 6749),
 * JWT Bearer (RFC 7523), and mTLS (RFC 8705) authentication methods.
 */
class IAuthClient {
  /**
   * Authenticate using Client Credentials flow (OAuth2 RFC 6749)
   * @param {string[]} [scopes] - Scopes to request
   * @returns {Promise<AuthResult>}
   */
  async authenticateClientCredentialsAsync(scopes = null) {
    throw new Error('Method must be implemented');
  }

  /**
   * Authenticate using JWT Bearer flow (RFC 7523)
   * @param {string} [subject] - JWT subject
   * @param {string[]} [scopes] - Scopes to request
   * @returns {Promise<AuthResult>}
   */
  async authenticateJwtBearerAsync(subject = null, scopes = null) {
    throw new Error('Method must be implemented');
  }

  /**
   * Authenticate using Authorization Code flow (OAuth2 RFC 6749)
   * @param {string} authorizationCode - Authorization code
   * @param {string} redirectUri - Redirect URI
   * @param {string} [codeVerifier] - PKCE code verifier
   * @returns {Promise<AuthResult>}
   */
  async authenticateAuthorizationCodeAsync(authorizationCode, redirectUri, codeVerifier = null) {
    throw new Error('Method must be implemented');
  }

  /**
   * Start Authorization Code + PKCE flow (RFC 7636)
   * @param {string} redirectUri - Redirect URI
   * @param {string[]} [scopes] - Scopes to request
   * @param {string} [state] - State parameter
   * @returns {Promise<{authorizationUrl: string, codeVerifier: string, state: string}>}
   */
  async startAuthorizationCodeFlowAsync(redirectUri, scopes = null, state = null) {
    throw new Error('Method must be implemented');
  }

  /**
   * Refresh access token using refresh token
   * @param {string} refreshToken - Refresh token
   * @returns {Promise<AuthResult>}
   */
  async refreshTokenAsync(refreshToken) {
    throw new Error('Method must be implemented');
  }

  /**
   * Get current valid token (automatically refreshes if needed)
   * @returns {Promise<AuthToken|null>}
   */
  async getValidTokenAsync() {
    throw new Error('Method must be implemented');
  }

  /**
   * Revoke a token
   * @param {string} token - Token to revoke
   * @param {string} [tokenTypeHint] - Token type hint
   * @returns {Promise<boolean>}
   */
  async revokeTokenAsync(token, tokenTypeHint = null) {
    throw new Error('Method must be implemented');
  }

  /**
   * Introspect a token
   * @param {string} token - Token to introspect
   * @returns {Promise<boolean>}
   */
  async introspectTokenAsync(token) {
    throw new Error('Method must be implemented');
  }

  /**
   * Test connection to authentication server
   * @returns {Promise<boolean>}
   */
  async testConnectionAsync() {
    throw new Error('Method must be implemented');
  }

  /**
   * Get authentication server information
   * @returns {Promise<AuthServerInfo|null>}
   */
  async getServerInfoAsync() {
    throw new Error('Method must be implemented');
  }

  /**
   * Clear stored tokens
   */
  clearTokens() {
    throw new Error('Method must be implemented');
  }

  /**
   * Get current token (if any)
   * @returns {AuthToken|null}
   */
  get currentToken() {
    throw new Error('Property must be implemented');
  }

  /**
   * Check if client has valid authentication
   * @returns {boolean}
   */
  get isAuthenticated() {
    throw new Error('Property must be implemented');
  }

  // Synchronous versions for compatibility
  authenticateClientCredentials(scopes = null) {
    return this.authenticateClientCredentialsAsync(scopes);
  }

  authenticateJwtBearer(subject = null, scopes = null) {
    return this.authenticateJwtBearerAsync(subject, scopes);
  }

  authenticateAuthorizationCode(authorizationCode, redirectUri, codeVerifier = null) {
    return this.authenticateAuthorizationCodeAsync(authorizationCode, redirectUri, codeVerifier);
  }

  refreshToken(refreshToken) {
    return this.refreshTokenAsync(refreshToken);
  }

  getValidToken() {
    return this.getValidTokenAsync();
  }

  revokeToken(token, tokenTypeHint = null) {
    return this.revokeTokenAsync(token, tokenTypeHint);
  }

  introspectToken(token) {
    return this.introspectTokenAsync(token);
  }

  testConnection() {
    return this.testConnectionAsync();
  }

  getServerInfo() {
    return this.getServerInfoAsync();
  }
}

// Concrete implementations

/**
 * In-memory token storage implementation
 */
class InMemoryTokenStorage extends IAuthTokenStorage {
  constructor() {
    super();
    this._tokens = new Map();
  }

  async storeTokenAsync(clientId, token) {
    this._tokens.set(clientId, token);
  }

  getToken(clientId) {
    return this._tokens.get(clientId) || null;
  }

  clearToken(clientId) {
    this._tokens.delete(clientId);
  }

  clearAllTokens() {
    this._tokens.clear();
  }
}

/**
 * Console logger implementation
 */
class ConsoleAuthLogger extends IAuthLogger {
  constructor(prefix = 'Auth') {
    super();
    this.prefix = prefix;
  }

  logInfo(message) {
    console.log(`[${new Date().toISOString()}] [${this.prefix}] INFO: ${message}`);
  }

  logError(message) {
    console.error(`[${new Date().toISOString()}] [${this.prefix}] ERROR: ${message}`);
  }

  logDebug(message) {
    console.log(`[${new Date().toISOString()}] [${this.prefix}] DEBUG: ${message}`);
  }
}

/**
 * Null logger implementation (no logging)
 */
class NullAuthLogger extends IAuthLogger {
  logInfo(message) {
    // No-op
  }

  logError(message) {
    // No-op
  }

  logDebug(message) {
    // No-op
  }
}

// Legacy OAuth2 interfaces for backward compatibility (deprecated)
// These will be removed in a future version - use Auth* interfaces instead

/** @deprecated Use AuthMode instead */
const OAuth2AuthMode = AuthMode;

/** @deprecated Use AuthConfigHelper instead */
const OAuth2ConfigHelper = AuthConfigHelper;

/** @deprecated Use IAuthTokenStorage instead */
const IOAuth2TokenStorage = IAuthTokenStorage;

/** @deprecated Use IAuthLogger instead */
const IOAuth2Logger = IAuthLogger;

/** @deprecated Use IAuthClient instead */
const IOAuth2AuthClient = IAuthClient;

/** @deprecated Use InMemoryTokenStorage instead */
const InMemoryOAuth2TokenStorage = InMemoryTokenStorage;

/** @deprecated Use ConsoleAuthLogger instead */
const ConsoleOAuth2Logger = ConsoleAuthLogger;

/** @deprecated Use NullAuthLogger instead */
const NullOAuth2Logger = NullAuthLogger;

// Export for Node.js and browser environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    AuthMode,
    AuthConfigHelper,
    IAuthTokenStorage,
    IAuthLogger,
    IAuthClient,
    InMemoryTokenStorage,
    ConsoleAuthLogger,
    NullAuthLogger,
    // Legacy exports for backward compatibility
    OAuth2AuthMode,
    OAuth2ConfigHelper,
    IOAuth2TokenStorage,
    IOAuth2Logger,
    IOAuth2AuthClient,
    InMemoryOAuth2TokenStorage,
    ConsoleOAuth2Logger,
    NullOAuth2Logger
  };
}

// Export for ES6 modules
if (typeof window !== 'undefined') {
  window.Auth = {
    AuthMode,
    AuthConfigHelper,
    IAuthTokenStorage,
    IAuthLogger,
    IAuthClient,
    InMemoryTokenStorage,
    ConsoleAuthLogger,
    NullAuthLogger,
    // Legacy exports for backward compatibility
    OAuth2: {
      AuthMode: OAuth2AuthMode,
      ConfigHelper: OAuth2ConfigHelper,
      TokenStorage: IOAuth2TokenStorage,
      Logger: IOAuth2Logger,
      AuthClient: IOAuth2AuthClient,
      InMemoryTokenStorage: InMemoryOAuth2TokenStorage,
      ConsoleLogger: ConsoleOAuth2Logger,
      NullLogger: NullOAuth2Logger
    }
  };
}
