/**
 * Authentication Client Factory for TypeScript/JavaScript
 * 
 * This module provides factory methods and builder pattern for creating authentication clients
 * in the CoyoteSense platform. Supports multiple authentication standards:
 * - OAuth2 Client Credentials (RFC 6749)
 * - OAuth2 Authorization Code (RFC 6749) 
 * - OAuth2 + PKCE (RFC 7636)
 * - JWT Bearer (RFC 7523)
 * - mTLS Client Credentials (RFC 8705)
 */

import { CoyoteHttpClient } from '../../../http/ts';
import { 
  AuthClientConfig, 
  IAuthTokenStorage, 
  IAuthLogger,
  AuthMode 
} from '../../interfaces/ts/auth-interfaces';

// Import the actual client implementation
import { AuthClient } from '../../clients/typescript/auth-client';

// Factory Pattern for Easy Client Creation

export class AuthClientBuilder {
  private config: Partial<AuthClientConfig> = {};
  private _tokenStorage?: IAuthTokenStorage;
  private _logger?: IAuthLogger;

  /**
   * Set authentication server URL
   */
  serverUrl(url: string): AuthClientBuilder {
    this.config.serverUrl = url;
    return this;
  }

  /**
   * Set client credentials (ID and secret)
   */
  clientCredentials(clientId: string, clientSecret?: string): AuthClientBuilder {
    this.config.clientId = clientId;
    this.config.clientSecret = clientSecret;
    return this;
  }

  /**
   * Set authentication mode
   */
  authMode(mode: AuthMode): AuthClientBuilder {
    this.config.authMode = mode;
    return this;
  }

  /**
   * Set mTLS certificates for mTLS authentication
   */
  mtlsCertificates(certPath: string, keyPath: string, caCertPath?: string): AuthClientBuilder {
    this.config.clientCertPath = certPath;
    this.config.clientKeyPath = keyPath;
    this.config.caCertPath = caCertPath;
    return this;
  }

  /**
   * Set JWT settings for JWT Bearer authentication
   */
  jwtSettings(signingKeyPath: string, issuer: string, audience: string, algorithm?: string): AuthClientBuilder {
    this.config.jwtSigningKeyPath = signingKeyPath;
    this.config.jwtIssuer = issuer;
    this.config.jwtAudience = audience;
    this.config.jwtAlgorithm = algorithm || 'RS256';
    return this;
  }

  /**
   * Set redirect URI for Authorization Code flows
   */
  redirectUri(uri: string): AuthClientBuilder {
    this.config.redirectUri = uri;
    return this;
  }

  /**
   * Enable PKCE for Authorization Code flow
   */
  enablePkce(enable: boolean = true): AuthClientBuilder {
    this.config.usePkce = enable;
    return this;
  }

  /**
   * Set default scopes
   */
  defaultScopes(scopes: string[]): AuthClientBuilder {
    this.config.defaultScopes = scopes;
    return this;
  }

  /**
   * Set request timeout
   */
  timeout(timeoutMs: number): AuthClientBuilder {
    this.config.timeoutMs = timeoutMs;
    return this;
  }

  /**
   * Set custom headers
   */
  customHeaders(headers: Record<string, string>): AuthClientBuilder {
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
  ): AuthClientBuilder {
    this.config.enableAutoRefresh = enabled;
    this.config.refreshMarginSeconds = marginSeconds;
    this.config.refreshCheckIntervalMs = checkIntervalMs;
    return this;
  }

  /**
   * Set token storage implementation
   */
  tokenStorage(storage: IAuthTokenStorage): AuthClientBuilder {
    this._tokenStorage = storage;
    return this;
  }

  /**
   * Set logger implementation
   */
  logger(logger: IAuthLogger): AuthClientBuilder {
    this._logger = logger;
    return this;
  }

  /**
   * Build the authentication client
   */
  build(httpClient?: CoyoteHttpClient): AuthClient {
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

    const finalConfig: AuthClientConfig = {
      authMode: this.config.authMode || AuthMode.ClientCredentials,
      serverUrl: this.config.serverUrl,
      clientId: this.config.clientId,
      clientSecret: this.config.clientSecret,
      defaultScopes: this.config.defaultScopes || [],
      timeoutMs: this.config.timeoutMs || 30000,
      customHeaders: this.config.customHeaders || {},
      enableAutoRefresh: this.config.enableAutoRefresh ?? true,
      refreshMarginSeconds: this.config.refreshMarginSeconds || 300,
      refreshCheckIntervalMs: this.config.refreshCheckIntervalMs || 60000,
      // Include all other configuration properties
      clientCertPath: this.config.clientCertPath,
      clientKeyPath: this.config.clientKeyPath,
      caCertPath: this.config.caCertPath,
      jwtSigningKeyPath: this.config.jwtSigningKeyPath,
      jwtAlgorithm: this.config.jwtAlgorithm,
      jwtIssuer: this.config.jwtIssuer,
      jwtAudience: this.config.jwtAudience,
      redirectUri: this.config.redirectUri,
      usePkce: this.config.usePkce,
      refreshBufferSeconds: this.config.refreshBufferSeconds,
      autoRefresh: this.config.autoRefresh,
      maxRetryAttempts: this.config.maxRetryAttempts,
      retryDelayMs: this.config.retryDelayMs,
      verifySsl: this.config.verifySsl
    };

    return new AuthClient(
      finalConfig,
      clientToUse,
      this._tokenStorage,
      this._logger
    );
  }
}

export class AuthClientFactory {
  /**
   * Create a new authentication client builder
   */
  static create(): AuthClientBuilder {
    return new AuthClientBuilder();
  }

  /**
   * Create authentication client with minimal configuration
   */
  static createSimple(
    serverUrl: string, 
    clientId: string, 
    clientSecret?: string,
    httpClient?: CoyoteHttpClient
  ): AuthClient {
    return AuthClientFactory.create()
      .serverUrl(serverUrl)
      .clientCredentials(clientId, clientSecret)
      .build(httpClient);
  }

  /**
   * Create authentication client for Client Credentials flow
   */
  static createClientCredentials(
    serverUrl: string,
    clientId: string,
    clientSecret: string,
    scopes?: string[],
    httpClient?: CoyoteHttpClient
  ): AuthClient {
    const builder = AuthClientFactory.create()
      .serverUrl(serverUrl)
      .clientCredentials(clientId, clientSecret)
      .authMode(AuthMode.ClientCredentials);

    if (scopes) {
      builder.defaultScopes(scopes);
    }

    return builder.build(httpClient);
  }

  /**
   * Create authentication client for Client Credentials with mTLS flow
   */
  static createClientCredentialsMtls(
    serverUrl: string,
    clientId: string,
    clientCertPath: string,
    clientKeyPath: string,
    caCertPath?: string,
    scopes?: string[],
    httpClient?: CoyoteHttpClient
  ): AuthClient {
    const builder = AuthClientFactory.create()
      .serverUrl(serverUrl)
      .clientCredentials(clientId)
      .authMode(AuthMode.ClientCredentialsMtls)
      .mtlsCertificates(clientCertPath, clientKeyPath, caCertPath);

    if (scopes) {
      builder.defaultScopes(scopes);
    }

    return builder.build(httpClient);
  }

  /**
   * Create authentication client for JWT Bearer flow
   */
  static createJwtBearer(
    serverUrl: string,
    clientId: string,
    jwtSigningKeyPath: string,
    jwtIssuer: string,
    jwtAudience: string,
    jwtAlgorithm?: string,
    scopes?: string[],
    httpClient?: CoyoteHttpClient
  ): AuthClient {
    const builder = AuthClientFactory.create()
      .serverUrl(serverUrl)
      .clientCredentials(clientId)
      .authMode(AuthMode.JwtBearer)
      .jwtSettings(jwtSigningKeyPath, jwtIssuer, jwtAudience, jwtAlgorithm);

    if (scopes) {
      builder.defaultScopes(scopes);
    }

    return builder.build(httpClient);
  }

  /**
   * Create authentication client for Authorization Code flow
   */
  static createAuthorizationCode(
    serverUrl: string,
    clientId: string,
    redirectUri: string,
    scopes?: string[],
    httpClient?: CoyoteHttpClient
  ): AuthClient {
    const builder = AuthClientFactory.create()
      .serverUrl(serverUrl)
      .clientCredentials(clientId) // No secret for public clients
      .authMode(AuthMode.AuthorizationCode)
      .redirectUri(redirectUri);

    if (scopes) {
      builder.defaultScopes(scopes);
    }

    return builder.build(httpClient);
  }

  /**
   * Create authentication client for Authorization Code with PKCE flow
   */
  static createAuthorizationCodePkce(
    serverUrl: string,
    clientId: string,
    redirectUri: string,
    scopes?: string[],
    httpClient?: CoyoteHttpClient
  ): AuthClient {
    const builder = AuthClientFactory.create()
      .serverUrl(serverUrl)
      .clientCredentials(clientId) // No secret for public clients
      .authMode(AuthMode.AuthorizationCodePkce)
      .redirectUri(redirectUri)
      .enablePkce(true);

    if (scopes) {
      builder.defaultScopes(scopes);
    }

    return builder.build(httpClient);
  }
}

// Legacy aliases for backward compatibility
export const OAuth2AuthClientBuilder = AuthClientBuilder;
export const OAuth2AuthClientFactory = AuthClientFactory;
