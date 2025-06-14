/**
 * Multi-Standard Authentication Interfaces and Types for TypeScript/JavaScript
 * 
 * This module contains all the interface definitions and types for multi-standard authentication
 * in the CoyoteSense platform, supporting OAuth2 (RFC 6749), JWT Bearer (RFC 7523), 
 * and mTLS (RFC 8705) authentication methods.
 */

// Authentication Modes

/**
 * Authentication modes supported by the platform
 */
export enum AuthMode {
  /** Standard OAuth2 client credentials flow (RFC 6749) */
  ClientCredentials = 'client_credentials',
  
  /** Client credentials with mutual TLS authentication (RFC 8705) */
  ClientCredentialsMtls = 'client_credentials_mtls',
  
  /** JWT Bearer assertion flow (RFC 7523) */
  JwtBearer = 'jwt_bearer',
  
  /** Authorization code flow (RFC 6749) */
  AuthorizationCode = 'authorization_code',
  
  /** Authorization code flow with PKCE (RFC 7636) */
  AuthorizationCodePkce = 'authorization_code_pkce'
}

// Authentication Configuration and Models

export interface AuthClientConfig {
  /** Authentication mode to use */
  authMode?: AuthMode;
  /** Authentication server base URL */
  serverUrl: string;
  /** Client ID for authentication */
  clientId: string;
  /** Client secret for authentication (optional for public clients) */
  clientSecret?: string;
  /** Default scopes to request */
  defaultScopes?: string[];
  
  // mTLS settings
  /** Client certificate path for mTLS authentication */
  clientCertPath?: string;
  /** Client certificate key path for mTLS authentication */
  clientKeyPath?: string;
  /** CA certificate path for mTLS authentication */
  caCertPath?: string;
  
  // JWT Bearer settings
  /** JWT signing key path for JWT Bearer flow */
  jwtSigningKeyPath?: string;
  /** JWT algorithm for JWT Bearer flow */
  jwtAlgorithm?: string;
  /** JWT issuer for JWT Bearer flow */
  jwtIssuer?: string;
  /** JWT audience for JWT Bearer flow */
  jwtAudience?: string;
  
  // Authorization Code settings
  /** Redirect URI for authorization code flows */
  redirectUri?: string;
  /** Use PKCE for authorization code flow */
  usePkce?: boolean;
  
  // Token management
  /** Token refresh buffer in seconds (refresh before expiry) */
  refreshBufferSeconds?: number;
  /** Enable automatic token refresh */
  autoRefresh?: boolean;
  /** Maximum retry attempts for token operations */
  maxRetryAttempts?: number;
  /** Retry delay in milliseconds */
  retryDelayMs?: number;
  
  // HTTP settings
  /** Default timeout for authentication requests in milliseconds */
  timeoutMs?: number;
  /** Verify SSL certificates */
  verifySsl?: boolean;
  /** Custom headers to include in authentication requests */
  customHeaders?: Record<string, string>;
  /** Enable automatic token refresh */
  enableAutoRefresh?: boolean;
  /** Token refresh margin in seconds (refresh when token expires in this time) */
  refreshMarginSeconds?: number;
  /** Background refresh check interval in milliseconds */
  refreshCheckIntervalMs?: number;
}

/**
 * Authentication client configuration helper functions
 */
export class AuthConfigHelper {
  /** Check if using client credentials mode */
  static isClientCredentialsMode(config: AuthClientConfig): boolean {
    return config.authMode === AuthMode.ClientCredentials;
  }

  /** Check if using mTLS mode */
  static isMtlsMode(config: AuthClientConfig): boolean {
    return config.authMode === AuthMode.ClientCredentialsMtls;
  }

  /** Check if using JWT Bearer mode */
  static isJwtBearerMode(config: AuthClientConfig): boolean {
    return config.authMode === AuthMode.JwtBearer;
  }

  /** Check if using any authorization code mode */
  static isAuthorizationCodeMode(config: AuthClientConfig): boolean {
    return config.authMode === AuthMode.AuthorizationCode || 
           config.authMode === AuthMode.AuthorizationCodePkce;
  }

  /** Check if certificates are required for this mode */
  static requiresCertificates(config: AuthClientConfig): boolean {
    return this.isMtlsMode(config);
  }

  /** Check if client secret is required for this mode */
  static requiresClientSecret(config: AuthClientConfig): boolean {
    return this.isClientCredentialsMode(config) || this.isMtlsMode(config);
  }

  /** Check if JWT key is required for this mode */
  static requiresJwtKey(config: AuthClientConfig): boolean {
    return this.isJwtBearerMode(config);
  }

  /** Check if redirect URI is required for this mode */
  static requiresRedirectUri(config: AuthClientConfig): boolean {
    return this.isAuthorizationCodeMode(config);
  }

  /** Validate configuration for the selected authentication mode */
  static isValid(config: AuthClientConfig): boolean {
    if (!config.clientId || !config.serverUrl) {
      return false;
    }

    switch (config.authMode) {
      case AuthMode.ClientCredentials:
        return !!config.clientSecret;
      
      case AuthMode.ClientCredentialsMtls:
        return !!config.clientSecret && !!config.clientCertPath && !!config.clientKeyPath;
      
      case AuthMode.JwtBearer:
        return !!config.jwtSigningKeyPath;
      
      case AuthMode.AuthorizationCode:
      case AuthMode.AuthorizationCodePkce:
        return !!config.redirectUri;
      
      default:
        return false;
    }
  }
}

export interface AuthToken {
  /** Access token value */
  accessToken: string;
  /** Token type (typically 'Bearer') */
  tokenType: string;
  /** Token expiration time as Unix timestamp */
  expiresAt: number;
  /** Refresh token (if available) */
  refreshToken?: string;
  /** Token scopes */
  scopes?: string[];
  /** ID token (for OpenID Connect) */
  idToken?: string;
}

export interface AuthResult {
  /** Whether the authentication was successful */
  success: boolean;
  /** Access token (if successful) */
  token?: AuthToken;
  /** Error code (if failed) */
  error?: string;
  /** Error description (if failed) */
  errorDescription?: string;
  /** Server info (if available) */
  serverInfo?: AuthServerInfo;
}

export interface AuthServerInfo {
  /** Authentication server issuer */
  issuer?: string;
  /** Authorization endpoint URL */
  authorizationEndpoint?: string;
  /** Token endpoint URL */
  tokenEndpoint?: string;
  /** Token introspection endpoint URL */
  introspectionEndpoint?: string;
  /** Token revocation endpoint URL */
  revocationEndpoint?: string;
  /** Supported grant types */
  grantTypesSupported?: string[];
  /** Supported response types */
  responseTypesSupported?: string[];
  /** Supported scopes */
  scopesSupported?: string[];
}

export interface AuthPKCEData {
  /** Code verifier for PKCE */
  codeVerifier: string;
  /** Code challenge for PKCE */
  codeChallenge: string;
  /** Code challenge method (S256 or plain) */
  codeChallengeMethod: string;
  /** Authorization state parameter */
  state: string;
}

// Authentication Request/Response Models (matching server API)

export interface AuthTokenRequest {
  grant_type: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
  assertion?: string;
  code?: string;
  redirect_uri?: string;
  refresh_token?: string;
  code_verifier?: string;
}

export interface AuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
}

export interface AuthErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
}

export interface AuthIntrospectRequest {
  token: string;
  token_type_hint?: string;
}

export interface AuthIntrospectResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  username?: string;
  token_type?: string;
  exp?: number;
  iat?: number;
  sub?: string;
  aud?: string;
  iss?: string;
  jti?: string;
}

// Abstract Interfaces

export abstract class AuthTokenStorage {
  /** Store a token with the specified key */
  abstract storeTokenAsync(key: string, token: AuthToken): Promise<void>;
  
  /** Retrieve a token by key */
  abstract retrieveTokenAsync(key: string): Promise<AuthToken | null>;
  
  /** Remove a token by key */
  abstract removeTokenAsync(key: string): Promise<void>;
  
  /** Clear all stored tokens */
  abstract clearAllTokensAsync(): Promise<void>;
}

export abstract class AuthLogger {
  /** Log debug message */
  abstract debug(message: string, ...args: any[]): void;
  
  /** Log info message */
  abstract info(message: string, ...args: any[]): void;
  
  /** Log warning message */
  abstract warn(message: string, ...args: any[]): void;
  
  /** Log error message */
  abstract error(message: string, ...args: any[]): void;
}

// Concrete Implementations

export class MemoryAuthTokenStorage extends AuthTokenStorage {
  private readonly tokens = new Map<string, AuthToken>();

  async storeTokenAsync(key: string, token: AuthToken): Promise<void> {
    this.tokens.set(key, { ...token });
  }

  async retrieveTokenAsync(key: string): Promise<AuthToken | null> {
    const token = this.tokens.get(key);
    return token ? { ...token } : null;
  }

  async removeTokenAsync(key: string): Promise<void> {
    this.tokens.delete(key);
  }

  async clearAllTokensAsync(): Promise<void> {
    this.tokens.clear();
  }
}

export class ConsoleAuthLogger extends AuthLogger {
  constructor(private readonly prefix: string = '[AuthClient]') {
    super();
  }

  debug(message: string, ...args: any[]): void {
    console.debug(`${this.prefix} DEBUG: ${message}`, ...args);
  }

  info(message: string, ...args: any[]): void {
    console.info(`${this.prefix} INFO: ${message}`, ...args);
  }

  warn(message: string, ...args: any[]): void {
    console.warn(`${this.prefix} WARN: ${message}`, ...args);
  }

  error(message: string, ...args: any[]): void {
    console.error(`${this.prefix} ERROR: ${message}`, ...args);
  }
}

export class NullAuthLogger extends AuthLogger {
  debug(message: string, ...args: any[]): void {}
  info(message: string, ...args: any[]): void {}
  warn(message: string, ...args: any[]): void {}
  error(message: string, ...args: any[]): void {}
}

// Main Authentication Client Interface

export interface IAuthClient {
  // Client Credentials Flow
  /**
   * Authenticate using Client Credentials flow (OAuth2 RFC 6749)
   * @param scopes Requested scopes
   * @returns Authentication result
   */
  clientCredentialsAsync(scopes?: string[]): Promise<AuthResult>;

  // JWT Bearer Flow
  /**
   * Authenticate using JWT Bearer assertion (RFC 7523)
   * @param assertion JWT assertion token
   * @param scopes Requested scopes
   * @returns Authentication result
   */
  jwtBearerAsync(assertion: string, scopes?: string[]): Promise<AuthResult>;

  // Authorization Code Flow
  /**
   * Start Authorization Code flow by generating authorization URL (OAuth2 RFC 6749)
   * @param redirectUri Redirect URI after authorization
   * @param scopes Requested scopes
   * @param state Optional state parameter
   * @param usePKCE Whether to use PKCE (RFC 7636)
   * @returns Authorization URL and PKCE data
   */
  startAuthorizationCodeFlow(
    redirectUri: string, 
    scopes?: string[], 
    state?: string, 
    usePKCE?: boolean
  ): { authorizationUrl: string; pkceData?: AuthPKCEData };

  /**
   * Complete Authorization Code flow by exchanging code for token
   * @param code Authorization code received from callback
   * @param redirectUri Redirect URI used in authorization request
   * @param pkceData PKCE data from startAuthorizationCodeFlow (if used)
   * @returns Authentication result
   */
  completeAuthorizationCodeFlow(
    code: string, 
    redirectUri: string, 
    pkceData?: AuthPKCEData
  ): Promise<AuthResult>;

  // Token Refresh
  /**
   * Refresh an access token using refresh token
   * @param refreshToken Refresh token
   * @param scopes Optional scopes to request
   * @returns Authentication result
   */
  refreshTokenAsync(refreshToken: string, scopes?: string[]): Promise<AuthResult>;

  // Token Management
  /**
   * Get stored token for client
   * @returns Stored authentication token or null
   */
  getStoredTokenAsync(): Promise<AuthToken | null>;

  /**
   * Store token for client
   * @param token Token to store
   */
  storeTokenAsync(token: AuthToken): Promise<void>;

  /**
   * Remove stored token for client
   */
  removeStoredTokenAsync(): Promise<void>;

  /**
   * Check if stored token is valid and not expired
   * @param marginSeconds Expiration margin in seconds
   * @returns True if token is valid
   */
  hasValidTokenAsync(marginSeconds?: number): Promise<boolean>;

  // Token Introspection
  /**
   * Introspect a token to check its validity and metadata
   * @param token Token to introspect
   * @param tokenTypeHint Optional hint about token type
   * @returns Token introspection result
   */
  introspectTokenAsync(token: string, tokenTypeHint?: string): Promise<AuthIntrospectResponse>;

  // Token Revocation
  /**
   * Revoke a token
   * @param token Token to revoke
   * @param tokenTypeHint Optional hint about token type
   * @returns True if revocation was successful
   */
  revokeTokenAsync(token: string, tokenTypeHint?: string): Promise<boolean>;

  // Server Discovery
  /**
   * Discover authentication server capabilities
   * @returns Server information
   */
  discoverServerAsync(): Promise<AuthServerInfo>;

  // Auto-refresh Management
  /**
   * Start automatic token refresh
   */
  startAutoRefresh(): void;

  /**
   * Stop automatic token refresh
   */
  stopAutoRefresh(): void;

  /**
   * Check if auto-refresh is enabled
   * @returns True if auto-refresh is running
   */
  isAutoRefreshRunning(): boolean;

  // Client Management
  /**
   * Get client configuration
   * @returns Client configuration
   */
  getConfig(): AuthClientConfig;

  /**
   * Dispose of client resources
   */
  dispose(): void;
}

// Legacy OAuth2 interfaces for backward compatibility (deprecated)
// These will be removed in a future version - use Auth* interfaces instead

/** @deprecated Use AuthMode instead */
export const OAuth2AuthMode = AuthMode;

/** @deprecated Use AuthClientConfig instead */
export type OAuth2ClientConfig = AuthClientConfig;

/** @deprecated Use AuthToken instead */
export type OAuth2Token = AuthToken;

/** @deprecated Use AuthResult instead */
export type OAuth2AuthResult = AuthResult;

/** @deprecated Use AuthServerInfo instead */
export type OAuth2ServerInfo = AuthServerInfo;

/** @deprecated Use AuthPKCEData instead */
export type OAuth2PKCEData = AuthPKCEData;

/** @deprecated Use IAuthClient instead */
export type IOAuth2AuthClient = IAuthClient;

/** @deprecated Use AuthConfigHelper instead */
export const OAuth2ConfigHelper = AuthConfigHelper;
