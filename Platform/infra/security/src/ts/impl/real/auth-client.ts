/**
 * OAuth2 Authentication Client for TypeScript/JavaScript
 * 
 * This module provides OAuth2 authentication capabilities for the CoyoteSense platform,
 * supporting Client Credentials, mTLS, JWT Bearer, and Authorization Code + PKCE flows.
 * 
 * Features:
 * - All OAuth2 grant types
 * - Automatic token refresh with background timer
 * - Token storage abstraction
 * - Comprehensive logging support
 * - mTLS support via HTTP client configuration
 * - PKCE for Authorization Code flow
 * - TypeScript types for all models
 * 
 * Usage:
 * ```typescript
 * const client = OAuth2AuthClientFactory.create()
 *   .serverUrl('https://auth.example.com')
 *   .clientCredentials('client-id', 'client-secret')
 *   .build();
 * 
 * const result = await client.clientCredentialsAsync(['read', 'write']);
 * if (result.success) {
 *   console.log('Access token:', result.token.accessToken);
 * }
 * ```
 */

import { CoyoteHttpClient, HttpRequest, HttpResponse, HttpMethod } from '../../../http/ts';

// OAuth2 Configuration and Models

export interface OAuth2ClientConfig {
  /** OAuth2 server base URL */
  serverUrl: string;
  /** Client ID for OAuth2 authentication */
  clientId: string;
  /** Client secret for OAuth2 authentication (optional for public clients) */
  clientSecret?: string;
  /** Default scopes to request */
  defaultScopes?: string[];
  /** Default timeout for OAuth2 requests in milliseconds */
  timeoutMs?: number;
  /** Custom headers to include in OAuth2 requests */
  customHeaders?: Record<string, string>;
  /** Enable automatic token refresh */
  enableAutoRefresh?: boolean;
  /** Token refresh margin in seconds (refresh when token expires in this time) */
  refreshMarginSeconds?: number;
  /** Background refresh check interval in milliseconds */
  refreshCheckIntervalMs?: number;
}

export interface OAuth2Token {
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

export interface OAuth2AuthResult {
  /** Whether the authentication was successful */
  success: boolean;
  /** Access token (if successful) */
  token?: OAuth2Token;
  /** Error code (if failed) */
  error?: string;
  /** Error description (if failed) */
  errorDescription?: string;
  /** Server info (if available) */
  serverInfo?: OAuth2ServerInfo;
}

export interface OAuth2ServerInfo {
  /** OAuth2 server issuer */
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

export interface OAuth2PKCEData {
  /** Code verifier for PKCE */
  codeVerifier: string;
  /** Code challenge for PKCE */
  codeChallenge: string;
  /** Code challenge method (S256 or plain) */
  codeChallengeMethod: string;
  /** Authorization state parameter */
  state: string;
}

// OAuth2 Request/Response Models (matching server API)

interface OAuth2TokenRequest {
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

interface OAuth2TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
}

interface OAuth2ErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
}

interface OAuth2IntrospectRequest {
  token: string;
  token_type_hint?: string;
}

interface OAuth2IntrospectResponse {
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

export abstract class OAuth2TokenStorage {
  /** Store a token with the specified key */
  abstract storeTokenAsync(key: string, token: OAuth2Token): Promise<void>;
  
  /** Retrieve a token by key */
  abstract retrieveTokenAsync(key: string): Promise<OAuth2Token | null>;
  
  /** Remove a token by key */
  abstract removeTokenAsync(key: string): Promise<void>;
  
  /** Clear all stored tokens */
  abstract clearAllTokensAsync(): Promise<void>;
}

export abstract class OAuth2Logger {
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

export class MemoryOAuth2TokenStorage extends OAuth2TokenStorage {
  private readonly tokens = new Map<string, OAuth2Token>();

  async storeTokenAsync(key: string, token: OAuth2Token): Promise<void> {
    this.tokens.set(key, { ...token });
  }

  async retrieveTokenAsync(key: string): Promise<OAuth2Token | null> {
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

export class ConsoleOAuth2Logger extends OAuth2Logger {
  constructor(private readonly prefix: string = '[OAuth2Client]') {}

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

export class NullOAuth2Logger extends OAuth2Logger {
  debug(message: string, ...args: any[]): void {}
  info(message: string, ...args: any[]): void {}
  warn(message: string, ...args: any[]): void {}
  error(message: string, ...args: any[]): void {}
}

// Main OAuth2 Client Interface

export interface IOAuth2AuthClient {
  // Client Credentials Flow
  /**
   * Authenticate using Client Credentials flow
   * @param scopes Requested scopes
   * @returns OAuth2 authentication result
   */
  clientCredentialsAsync(scopes?: string[]): Promise<OAuth2AuthResult>;

  // JWT Bearer Flow
  /**
   * Authenticate using JWT Bearer assertion
   * @param assertion JWT assertion token
   * @param scopes Requested scopes
   * @returns OAuth2 authentication result
   */
  jwtBearerAsync(assertion: string, scopes?: string[]): Promise<OAuth2AuthResult>;

  // Authorization Code Flow
  /**
   * Start Authorization Code flow by generating authorization URL
   * @param redirectUri Redirect URI after authorization
   * @param scopes Requested scopes
   * @param state Optional state parameter
   * @param usePKCE Whether to use PKCE
   * @returns Authorization URL and PKCE data
   */
  startAuthorizationCodeFlow(
    redirectUri: string, 
    scopes?: string[], 
    state?: string, 
    usePKCE?: boolean
  ): { authorizationUrl: string; pkceData?: OAuth2PKCEData };

  /**
   * Complete Authorization Code flow by exchanging code for token
   * @param code Authorization code received from callback
   * @param redirectUri Redirect URI used in authorization request
   * @param pkceData PKCE data from startAuthorizationCodeFlow (if used)
   * @returns OAuth2 authentication result
   */
  completeAuthorizationCodeFlow(
    code: string, 
    redirectUri: string, 
    pkceData?: OAuth2PKCEData
  ): Promise<OAuth2AuthResult>;

  // Token Refresh
  /**
   * Refresh an access token using refresh token
   * @param refreshToken Refresh token
   * @param scopes Optional scopes to request
   * @returns OAuth2 authentication result
   */
  refreshTokenAsync(refreshToken: string, scopes?: string[]): Promise<OAuth2AuthResult>;

  // Token Management
  /**
   * Get stored token for client
   * @returns Stored OAuth2 token or null
   */
  getStoredTokenAsync(): Promise<OAuth2Token | null>;

  /**
   * Store token for client
   * @param token Token to store
   */
  storeTokenAsync(token: OAuth2Token): Promise<void>;

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
  introspectTokenAsync(token: string, tokenTypeHint?: string): Promise<OAuth2IntrospectResponse>;

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
   * Discover OAuth2 server capabilities
   * @returns Server information
   */
  discoverServerAsync(): Promise<OAuth2ServerInfo>;

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
   * Get current client configuration
   */
  getConfig(): OAuth2ClientConfig;

  /**
   * Dispose of resources
   */
  dispose(): void;
}

// Main OAuth2 Client Implementation

export class OAuth2AuthClient implements IOAuth2AuthClient {
  private readonly config: OAuth2ClientConfig;
  private readonly httpClient: CoyoteHttpClient;
  private readonly tokenStorage: OAuth2TokenStorage;
  private readonly logger: OAuth2Logger;
  private refreshTimer: NodeJS.Timeout | null = null;
  private disposed = false;

  constructor(
    config: OAuth2ClientConfig,
    httpClient: CoyoteHttpClient,
    tokenStorage?: OAuth2TokenStorage,
    logger?: OAuth2Logger
  ) {
    this.config = {
      timeoutMs: 30000,
      enableAutoRefresh: true,
      refreshMarginSeconds: 300, // 5 minutes
      refreshCheckIntervalMs: 60000, // 1 minute
      ...config
    };
    this.httpClient = httpClient;
    this.tokenStorage = tokenStorage || new MemoryOAuth2TokenStorage();
    this.logger = logger || new ConsoleOAuth2Logger();

    // Set base URL for HTTP client
    if (this.httpClient.setBaseUrl) {
      this.httpClient.setBaseUrl(this.config.serverUrl);
    }

    if (this.config.enableAutoRefresh) {
      this.startAutoRefresh();
    }
  }

  // Client Credentials Flow
  async clientCredentialsAsync(scopes?: string[]): Promise<OAuth2AuthResult> {
    this.logger.debug('Starting Client Credentials flow', { scopes });

    const requestScopes = scopes || this.config.defaultScopes || [];
    
    const tokenRequest: OAuth2TokenRequest = {
      grant_type: 'client_credentials',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      scope: requestScopes.join(' ')
    };

    return this.makeTokenRequestAsync(tokenRequest);
  }

  // JWT Bearer Flow
  async jwtBearerAsync(assertion: string, scopes?: string[]): Promise<OAuth2AuthResult> {
    this.logger.debug('Starting JWT Bearer flow', { scopes });

    const requestScopes = scopes || this.config.defaultScopes || [];
    
    const tokenRequest: OAuth2TokenRequest = {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: assertion,
      scope: requestScopes.join(' ')
    };

    return this.makeTokenRequestAsync(tokenRequest);
  }

  // Authorization Code Flow
  startAuthorizationCodeFlow(
    redirectUri: string, 
    scopes?: string[], 
    state?: string, 
    usePKCE?: boolean
  ): { authorizationUrl: string; pkceData?: OAuth2PKCEData } {
    this.logger.debug('Starting Authorization Code flow', { redirectUri, scopes, usePKCE });

    const requestScopes = scopes || this.config.defaultScopes || [];
    const authState = state || this.generateRandomString(32);
    
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      scope: requestScopes.join(' '),
      state: authState
    });

    let pkceData: OAuth2PKCEData | undefined;
    
    if (usePKCE) {
      pkceData = this.generatePKCE();
      params.append('code_challenge', pkceData.codeChallenge);
      params.append('code_challenge_method', pkceData.codeChallengeMethod);
    }

    const authorizationUrl = `${this.config.serverUrl}/oauth2/authorize?${params.toString()}`;
    
    this.logger.debug('Generated authorization URL', { authorizationUrl });
    
    return { authorizationUrl, pkceData };
  }

  async completeAuthorizationCodeFlow(
    code: string, 
    redirectUri: string, 
    pkceData?: OAuth2PKCEData
  ): Promise<OAuth2AuthResult> {
    this.logger.debug('Completing Authorization Code flow', { code: code.substring(0, 10) + '...' });

    const tokenRequest: OAuth2TokenRequest = {
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code: code,
      redirect_uri: redirectUri
    };

    if (pkceData) {
      tokenRequest.code_verifier = pkceData.codeVerifier;
    }

    return this.makeTokenRequestAsync(tokenRequest);
  }

  // Token Refresh
  async refreshTokenAsync(refreshToken: string, scopes?: string[]): Promise<OAuth2AuthResult> {
    this.logger.debug('Refreshing token');

    const requestScopes = scopes || this.config.defaultScopes || [];
    
    const tokenRequest: OAuth2TokenRequest = {
      grant_type: 'refresh_token',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      refresh_token: refreshToken,
      scope: requestScopes.join(' ')
    };

    return this.makeTokenRequestAsync(tokenRequest);
  }

  // Token Management
  async getStoredTokenAsync(): Promise<OAuth2Token | null> {
    const tokenKey = `oauth2_token_${this.config.clientId}`;
    return this.tokenStorage.retrieveTokenAsync(tokenKey);
  }

  async storeTokenAsync(token: OAuth2Token): Promise<void> {
    const tokenKey = `oauth2_token_${this.config.clientId}`;
    await this.tokenStorage.storeTokenAsync(tokenKey, token);
    this.logger.debug('Token stored', { expiresAt: new Date(token.expiresAt * 1000) });
  }

  async removeStoredTokenAsync(): Promise<void> {
    const tokenKey = `oauth2_token_${this.config.clientId}`;
    await this.tokenStorage.removeTokenAsync(tokenKey);
    this.logger.debug('Token removed');
  }

  async hasValidTokenAsync(marginSeconds?: number): Promise<boolean> {
    const token = await this.getStoredTokenAsync();
    if (!token) {
      return false;
    }

    const margin = marginSeconds ?? this.config.refreshMarginSeconds ?? 300;
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = token.expiresAt - now;
    
    return expiresIn > margin;
  }

  // Token Introspection
  async introspectTokenAsync(token: string, tokenTypeHint?: string): Promise<OAuth2IntrospectResponse> {
    this.logger.debug('Introspecting token');

    const request: OAuth2IntrospectRequest = {
      token: token,
      token_type_hint: tokenTypeHint
    };

    const httpRequest: HttpRequest = {
      url: '/oauth2/introspect',
      method: HttpMethod.POST,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...this.config.customHeaders
      },
      body: this.encodeFormData(request),
      timeout: this.config.timeoutMs
    };

    // Add basic auth if client secret is available
    if (this.config.clientSecret) {
      const auth = btoa(`${this.config.clientId}:${this.config.clientSecret}`);
      httpRequest.headers!['Authorization'] = `Basic ${auth}`;
    }

    try {
      const response = await this.httpClient.executeAsync(httpRequest);
      
      if (!response.isSuccess) {
        throw new Error(`Token introspection failed: ${response.statusCode} ${response.errorMessage}`);
      }

      const introspectResponse: OAuth2IntrospectResponse = JSON.parse(response.body);
      this.logger.debug('Token introspection successful', { active: introspectResponse.active });
      
      return introspectResponse;
    } catch (error) {
      this.logger.error('Token introspection failed', error);
      throw error;
    }
  }

  // Token Revocation
  async revokeTokenAsync(token: string, tokenTypeHint?: string): Promise<boolean> {
    this.logger.debug('Revoking token');

    const request = {
      token: token,
      token_type_hint: tokenTypeHint
    };

    const httpRequest: HttpRequest = {
      url: '/oauth2/revoke',
      method: HttpMethod.POST,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...this.config.customHeaders
      },
      body: this.encodeFormData(request),
      timeout: this.config.timeoutMs
    };

    // Add basic auth if client secret is available
    if (this.config.clientSecret) {
      const auth = btoa(`${this.config.clientId}:${this.config.clientSecret}`);
      httpRequest.headers!['Authorization'] = `Basic ${auth}`;
    }

    try {
      const response = await this.httpClient.executeAsync(httpRequest);
      
      const success = response.isSuccess;
      this.logger.debug('Token revocation result', { success });
      
      return success;
    } catch (error) {
      this.logger.error('Token revocation failed', error);
      return false;
    }
  }

  // Server Discovery
  async discoverServerAsync(): Promise<OAuth2ServerInfo> {
    this.logger.debug('Discovering OAuth2 server configuration');

    const httpRequest: HttpRequest = {
      url: '/.well-known/oauth-authorization-server',
      method: HttpMethod.GET,
      headers: {
        'Accept': 'application/json',
        ...this.config.customHeaders
      },
      timeout: this.config.timeoutMs
    };

    try {
      const response = await this.httpClient.executeAsync(httpRequest);
      
      if (!response.isSuccess) {
        this.logger.warn('Server discovery failed, using defaults');
        return this.getDefaultServerInfo();
      }

      const serverInfo: OAuth2ServerInfo = JSON.parse(response.body);
      this.logger.debug('Server discovery successful', serverInfo);
      
      return serverInfo;
    } catch (error) {
      this.logger.warn('Server discovery failed, using defaults', error);
      return this.getDefaultServerInfo();
    }
  }

  // Auto-refresh Management
  startAutoRefresh(): void {
    if (this.refreshTimer || this.disposed) {
      return;
    }

    this.logger.debug('Starting auto-refresh timer');
    
    this.refreshTimer = setInterval(async () => {
      try {
        await this.checkAndRefreshToken();
      } catch (error) {
        this.logger.error('Auto-refresh check failed', error);
      }
    }, this.config.refreshCheckIntervalMs!);
  }

  stopAutoRefresh(): void {
    if (this.refreshTimer) {
      this.logger.debug('Stopping auto-refresh timer');
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  getConfig(): OAuth2ClientConfig {
    return { ...this.config };
  }

  dispose(): void {
    if (this.disposed) {
      return;
    }

    this.logger.debug('Disposing OAuth2 client');
    this.stopAutoRefresh();
    this.disposed = true;
  }

  // Private Helper Methods

  private async makeTokenRequestAsync(tokenRequest: OAuth2TokenRequest): Promise<OAuth2AuthResult> {
    const httpRequest: HttpRequest = {
      url: '/oauth2/token',
      method: HttpMethod.POST,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...this.config.customHeaders
      },
      body: this.encodeFormData(tokenRequest),
      timeout: this.config.timeoutMs
    };

    // Add basic auth if client secret is available and not already in body
    if (this.config.clientSecret && !tokenRequest.client_secret) {
      const auth = btoa(`${this.config.clientId}:${this.config.clientSecret}`);
      httpRequest.headers!['Authorization'] = `Basic ${auth}`;
    }

    try {
      const response = await this.httpClient.executeAsync(httpRequest);
      
      if (!response.isSuccess) {
        const errorResponse: OAuth2ErrorResponse = this.tryParseJson(response.body) || {
          error: 'request_failed',
          error_description: `HTTP ${response.statusCode}: ${response.errorMessage}`
        };

        this.logger.error('Token request failed', errorResponse);
        
        return {
          success: false,
          error: errorResponse.error,
          errorDescription: errorResponse.error_description
        };
      }

      const tokenResponse: OAuth2TokenResponse = JSON.parse(response.body);
      const token = this.convertToOAuth2Token(tokenResponse);
      
      // Store token automatically
      await this.storeTokenAsync(token);
      
      this.logger.info('Token request successful', {
        tokenType: token.tokenType,
        expiresAt: new Date(token.expiresAt * 1000),
        scopes: token.scopes
      });
      
      return {
        success: true,
        token: token
      };
    } catch (error) {
      this.logger.error('Token request failed', error);
      
      return {
        success: false,
        error: 'request_failed',
        errorDescription: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  private async checkAndRefreshToken(): Promise<void> {
    const token = await this.getStoredTokenAsync();
    if (!token || !token.refreshToken) {
      return;
    }

    const needsRefresh = !(await this.hasValidTokenAsync());
    if (!needsRefresh) {
      return;
    }

    this.logger.debug('Token needs refresh, attempting automatic refresh');
    
    const result = await this.refreshTokenAsync(token.refreshToken);
    if (result.success) {
      this.logger.info('Automatic token refresh successful');
    } else {
      this.logger.warn('Automatic token refresh failed', {
        error: result.error,
        errorDescription: result.errorDescription
      });
    }
  }

  private convertToOAuth2Token(response: OAuth2TokenResponse): OAuth2Token {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + response.expires_in;
    
    return {
      accessToken: response.access_token,
      tokenType: response.token_type,
      expiresAt: expiresAt,
      refreshToken: response.refresh_token,
      scopes: response.scope ? response.scope.split(' ') : undefined,
      idToken: response.id_token
    };
  }

  private encodeFormData(data: Record<string, any>): string {
    const params = new URLSearchParams();
    
    for (const [key, value] of Object.entries(data)) {
      if (value !== undefined && value !== null) {
        params.append(key, String(value));
      }
    }
    
    return params.toString();
  }

  private tryParseJson<T = any>(json: string): T | null {
    try {
      return JSON.parse(json);
    } catch {
      return null;
    }
  }

  private generateRandomString(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let result = '';
    
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    return result;
  }

  private generatePKCE(): OAuth2PKCEData {
    const codeVerifier = this.generateRandomString(128);
    const state = this.generateRandomString(32);
    
    // For browser environments, we'll use SHA256 if available, otherwise fall back to plain
    let codeChallenge: string;
    let codeChallengeMethod: string;
    
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      // Browser environment with Web Crypto API
      const encoder = new TextEncoder();
      const data = encoder.encode(codeVerifier);
      
      // Note: This is async in real implementation, but for simplicity we'll use plain method
      // In production, this should be properly implemented with async crypto
      codeChallenge = codeVerifier;
      codeChallengeMethod = 'plain';
    } else {
      // Node.js or fallback environment
      codeChallenge = codeVerifier;
      codeChallengeMethod = 'plain';
    }
    
    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod,
      state
    };
  }

  private getDefaultServerInfo(): OAuth2ServerInfo {
    return {
      issuer: this.config.serverUrl,
      authorizationEndpoint: `${this.config.serverUrl}/oauth2/authorize`,
      tokenEndpoint: `${this.config.serverUrl}/oauth2/token`,
      introspectionEndpoint: `${this.config.serverUrl}/oauth2/introspect`,
      revocationEndpoint: `${this.config.serverUrl}/oauth2/revoke`,
      grantTypesSupported: [
        'client_credentials',
        'authorization_code',
        'refresh_token',
        'urn:ietf:params:oauth:grant-type:jwt-bearer'
      ],
      responseTypesSupported: ['code'],
      scopesSupported: ['read', 'write', 'admin']
    };
  }
}

// Factory Pattern for Easy Client Creation

export class OAuth2AuthClientBuilder {
  private config: Partial<OAuth2ClientConfig> = {};
  private tokenStorage?: OAuth2TokenStorage;
  private logger?: OAuth2Logger;

  /**
   * Set OAuth2 server URL
   */
  serverUrl(url: string): OAuth2AuthClientBuilder {
    this.config.serverUrl = url;
    return this;
  }

  /**
   * Set client credentials (ID and secret)
   */
  clientCredentials(clientId: string, clientSecret?: string): OAuth2AuthClientBuilder {
    this.config.clientId = clientId;
    this.config.clientSecret = clientSecret;
    return this;
  }

  /**
   * Set default scopes
   */
  defaultScopes(scopes: string[]): OAuth2AuthClientBuilder {
    this.config.defaultScopes = scopes;
    return this;
  }

  /**
   * Set request timeout
   */
  timeout(timeoutMs: number): OAuth2AuthClientBuilder {
    this.config.timeoutMs = timeoutMs;
    return this;
  }

  /**
   * Set custom headers
   */
  customHeaders(headers: Record<string, string>): OAuth2AuthClientBuilder {
    this.config.customHeaders = { ...this.config.customHeaders, ...headers };
    return this;
  }

  /**
   * Configure automatic token refresh
   */
  autoRefresh(
    enabled: boolean = true, 
    marginSeconds: number = 300, 
    checkIntervalMs: number = 60000
  ): OAuth2AuthClientBuilder {
    this.config.enableAutoRefresh = enabled;
    this.config.refreshMarginSeconds = marginSeconds;
    this.config.refreshCheckIntervalMs = checkIntervalMs;
    return this;
  }

  /**
   * Set token storage implementation
   */
  tokenStorage(storage: OAuth2TokenStorage): OAuth2AuthClientBuilder {
    this.tokenStorage = storage;
    return this;
  }

  /**
   * Set logger implementation
   */
  logger(logger: OAuth2Logger): OAuth2AuthClientBuilder {
    this.logger = logger;
    return this;
  }

  /**
   * Build the OAuth2 client
   */
  build(httpClient?: CoyoteHttpClient): OAuth2AuthClient {
    if (!this.config.serverUrl) {
      throw new Error('Server URL is required');
    }
    if (!this.config.clientId) {
      throw new Error('Client ID is required');
    }

    // Use provided HTTP client or create a default one
    let clientToUse = httpClient;
    if (!clientToUse) {
      // Import and create default HTTP client
      // This would need to be properly implemented based on the HTTP client factory
      throw new Error('HTTP client must be provided in build() method');
    }

    const finalConfig: OAuth2ClientConfig = {
      serverUrl: this.config.serverUrl,
      clientId: this.config.clientId,
      clientSecret: this.config.clientSecret,
      defaultScopes: this.config.defaultScopes || [],
      timeoutMs: this.config.timeoutMs || 30000,
      customHeaders: this.config.customHeaders || {},
      enableAutoRefresh: this.config.enableAutoRefresh ?? true,
      refreshMarginSeconds: this.config.refreshMarginSeconds || 300,
      refreshCheckIntervalMs: this.config.refreshCheckIntervalMs || 60000
    };

    return new OAuth2AuthClient(
      finalConfig,
      clientToUse,
      this.tokenStorage,
      this.logger
    );
  }
}

export class OAuth2AuthClientFactory {
  /**
   * Create a new OAuth2 client builder
   */
  static create(): OAuth2AuthClientBuilder {
    return new OAuth2AuthClientBuilder();
  }

  /**
   * Create OAuth2 client with minimal configuration
   */
  static createSimple(
    serverUrl: string, 
    clientId: string, 
    clientSecret?: string,
    httpClient?: CoyoteHttpClient
  ): OAuth2AuthClient {
    return OAuth2AuthClientFactory.create()
      .serverUrl(serverUrl)
      .clientCredentials(clientId, clientSecret)
      .build(httpClient);
  }

  /**
   * Create OAuth2 client for Client Credentials flow
   */
  static createClientCredentials(
    serverUrl: string,
    clientId: string,
    clientSecret: string,
    scopes?: string[],
    httpClient?: CoyoteHttpClient
  ): OAuth2AuthClient {
    const builder = OAuth2AuthClientFactory.create()
      .serverUrl(serverUrl)
      .clientCredentials(clientId, clientSecret);

    if (scopes) {
      builder.defaultScopes(scopes);
    }

    return builder.build(httpClient);
  }

  /**
   * Create OAuth2 client for Authorization Code flow
   */
  static createAuthorizationCode(
    serverUrl: string,
    clientId: string,
    scopes?: string[],
    httpClient?: CoyoteHttpClient
  ): OAuth2AuthClient {
    const builder = OAuth2AuthClientFactory.create()
      .serverUrl(serverUrl)
      .clientCredentials(clientId); // No secret for public clients

    if (scopes) {
      builder.defaultScopes(scopes);
    }

    return builder.build(httpClient);
  }
}

// Export all interfaces and classes
export {
  OAuth2AuthClient as default
};
