/**
 * OAuth2 Authentication Client Implementation for TypeScript/JavaScript
 */

import { 
  AuthClientConfig,
  TokenResponse,
  IntrospectResponse,
  ServerDiscoveryResponse,
  AuthError,
  OAuth2TokenStorage,
  OAuth2Logger,
  AuthMode,
  PKCEParams
} from '../interfaces/auth-interfaces';

// Re-export everything for easier importing
export {
  AuthClientConfig,
  TokenResponse,
  IntrospectResponse,
  ServerDiscoveryResponse,
  AuthError,
  OAuth2TokenStorage,
  OAuth2Logger,
  AuthMode
} from '../interfaces/auth-interfaces';

export interface OAuth2AuthResult {
  success: boolean;
  token?: TokenResponse;
  error?: string;
  errorDescription?: string | undefined;
}

export class OAuth2AuthClient {
  private config: AuthClientConfig;
  private tokenStorage: OAuth2TokenStorage | undefined;
  private logger: OAuth2Logger | undefined;

  constructor(
    config: AuthClientConfig,
    tokenStorage?: OAuth2TokenStorage,
    logger?: OAuth2Logger
  ) {
    this.config = config;
    this.tokenStorage = tokenStorage;
    this.logger = logger;
  }

  // Client Credentials Flow
  async clientCredentialsAsync(scopes?: string[]): Promise<OAuth2AuthResult> {
    try {
      this.logger?.debug('Starting client credentials flow');
      
      const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.config.clientId
      });

      if (this.config.clientSecret) {
        body.append('client_secret', this.config.clientSecret);
      }

      if (scopes?.length) {
        body.append('scope', scopes.join(' '));
      } else if (this.config.scopes?.length) {
        body.append('scope', this.config.scopes.join(' '));
      }

      const response = await fetch(this.config.tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: body.toString()
      });

      if (!response.ok) {
        const errorData = await response.json() as AuthError;
        return {
          success: false,
          error: errorData.error,
          errorDescription: errorData.error_description
        };
      }

      const token = await response.json() as TokenResponse;
      
      if (this.tokenStorage) {
        await this.tokenStorage.setToken('access_token', token.access_token);
      }

      return {
        success: true,
        token
      };
    } catch (error) {
      this.logger?.error('Client credentials flow failed', error);
      return {
        success: false,
        error: 'network_error',
        errorDescription: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // JWT Bearer Flow  
  async jwtBearerAsync(jwtToken: string, scopes?: string[]): Promise<OAuth2AuthResult> {
    try {
      const body = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwtToken,
        client_id: this.config.clientId
      });

      if (scopes?.length) {
        body.append('scope', scopes.join(' '));
      } else if (this.config.scopes?.length) {
        body.append('scope', this.config.scopes.join(' '));
      }

      const response = await fetch(this.config.tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: body.toString()
      });

      if (!response.ok) {
        const errorData = await response.json() as AuthError;
        return {
          success: false,
          error: errorData.error,
          errorDescription: errorData.error_description
        };
      }

      const token = await response.json() as TokenResponse;
      return {
        success: true,
        token
      };
    } catch (error) {
      return {
        success: false,
        error: 'network_error',
        errorDescription: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // Authorization Code Flow
  startAuthorizationCodeFlow(
    redirectUri: string, 
    scopes?: string[], 
    state?: string, 
    usePKCE?: boolean
  ): { authorizationUrl: string; pkceData?: any } {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: redirectUri
    });

    if (scopes?.length) {
      params.append('scope', scopes.join(' '));
    }

    if (state) {
      params.append('state', state);
    }

    // TODO: Implement PKCE if requested
    if (usePKCE) {
      // For now, just return basic URL without PKCE
    }

    return {
      authorizationUrl: `${this.config.authorizationUrl}?${params.toString()}`
    };
  }

  async completeAuthorizationCodeFlow(
    code: string, 
    redirectUri: string, 
    pkceData?: any
  ): Promise<OAuth2AuthResult> {
    try {
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: this.config.clientId
      });

      if (this.config.clientSecret) {
        body.append('client_secret', this.config.clientSecret);
      }

      // TODO: Add PKCE verifier if provided

      const response = await fetch(this.config.tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: body.toString()
      });

      if (!response.ok) {
        const errorData = await response.json() as AuthError;
        return {
          success: false,
          error: errorData.error,
          errorDescription: errorData.error_description
        };
      }

      const token = await response.json() as TokenResponse;
      return {
        success: true,
        token
      };
    } catch (error) {
      return {
        success: false,
        error: 'network_error',
        errorDescription: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // Refresh Token
  async refreshTokenAsync(refreshToken: string, scopes?: string[]): Promise<OAuth2AuthResult> {
    try {
      const body = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.config.clientId
      });

      if (this.config.clientSecret) {
        body.append('client_secret', this.config.clientSecret);
      }

      if (scopes?.length) {
        body.append('scope', scopes.join(' '));
      }

      const response = await fetch(this.config.tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: body.toString()
      });

      if (!response.ok) {
        const errorData = await response.json() as AuthError;
        return {
          success: false,
          error: errorData.error,
          errorDescription: errorData.error_description
        };
      }

      const token = await response.json() as TokenResponse;
      return {
        success: true,
        token
      };
    } catch (error) {
      return {
        success: false,
        error: 'network_error',
        errorDescription: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // Token Introspection
  async introspectTokenAsync(token: string, tokenTypeHint?: string): Promise<IntrospectResponse> {
    if (!this.config.introspectionUrl) {
      throw new Error('Introspection URL not configured');
    }

    const body = new URLSearchParams({
      token,
      client_id: this.config.clientId
    });

    if (this.config.clientSecret) {
      body.append('client_secret', this.config.clientSecret);
    }

    if (tokenTypeHint) {
      body.append('token_type_hint', tokenTypeHint);
    }

    const response = await fetch(this.config.introspectionUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    });

    if (!response.ok) {
      throw new Error(`Introspection failed: ${response.status}`);
    }

    return await response.json() as IntrospectResponse;
  }

  // Token Revocation
  async revokeTokenAsync(token: string, tokenTypeHint?: string): Promise<boolean> {
    if (!this.config.revocationUrl) {
      throw new Error('Revocation URL not configured');
    }

    const body = new URLSearchParams({
      token,
      client_id: this.config.clientId
    });

    if (this.config.clientSecret) {
      body.append('client_secret', this.config.clientSecret);
    }

    if (tokenTypeHint) {
      body.append('token_type_hint', tokenTypeHint);
    }

    const response = await fetch(this.config.revocationUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    });

    return response.ok;
  }

  // Server Discovery
  async discoverServerAsync(): Promise<ServerDiscoveryResponse> {
    if (!this.config.discoveryUrl) {
      throw new Error('Discovery URL not configured');
    }

    const response = await fetch(this.config.discoveryUrl);
    
    if (!response.ok) {
      throw new Error(`Server discovery failed: ${response.status}`);
    }

    return await response.json() as ServerDiscoveryResponse;
  }

  // Token Storage
  async getStoredTokenAsync(): Promise<string | null> {
    if (!this.tokenStorage) {
      return null;
    }
    return await this.tokenStorage.getToken('access_token');
  }

  async storeTokenAsync(token: string): Promise<void> {
    if (this.tokenStorage) {
      await this.tokenStorage.setToken('access_token', token);
    }
  }

  async removeStoredTokenAsync(): Promise<void> {
    if (this.tokenStorage) {
      await this.tokenStorage.removeToken('access_token');
    }
  }

  // Additional method aliases for test compatibility
  async getTokenWithAuthorizationCode(code: string, codeVerifier?: string): Promise<TokenResponse> {
    return this.exchangeCodeForToken(code, codeVerifier);
  }

  async refreshToken(refreshToken: string, scopes?: string[]): Promise<TokenResponse> {
    const result = await this.refreshTokenAsync(refreshToken, scopes);
    if (!result.success || !result.token) {
      throw new Error(result.error || 'Failed to refresh token');
    }
    return result.token;
  }

  async introspectToken(token: string, tokenTypeHint?: string): Promise<IntrospectResponse> {
    return this.introspectTokenAsync(token, tokenTypeHint);
  }

  async revokeToken(token: string, tokenTypeHint?: string): Promise<boolean> {
    return this.revokeTokenAsync(token, tokenTypeHint);
  }

  async discoverServerEndpoints(): Promise<ServerDiscoveryResponse> {
    return this.discoverServerAsync();
  }

  // Token storage management methods
  async getStoredAccessToken(): Promise<string | null> {
    return this.tokenStorage?.getToken('access_token') || null;
  }

  async getStoredRefreshToken(): Promise<string | null> {
    return this.tokenStorage?.getToken('refresh_token') || null;
  }

  async clearStoredTokens(): Promise<void> {
    await this.tokenStorage?.clear();
  }

  // Token validation and refresh helpers
  async needsTokenRefresh(): Promise<boolean> {
    const token = await this.getStoredAccessToken();
    if (!token) return true;

    // For demonstration purposes, return false
    // In real implementation, would check token expiry
    return false;
  }

  async getValidAccessToken(): Promise<TokenResponse> {
    const needsRefresh = await this.needsTokenRefresh();
    if (needsRefresh) {
      return this.getTokenWithClientCredentials();
    }

    const accessToken = await this.getStoredAccessToken();
    if (!accessToken) {
      return this.getTokenWithClientCredentials();
    }

    return {
      access_token: accessToken,
      token_type: 'Bearer'
    };
  }

  // Auto-refresh (stub implementation)
  startAutoRefresh(): void {
    this.logger?.debug('Auto-refresh started');
  }

  stopAutoRefresh(): void {
    this.logger?.debug('Auto-refresh stopped');
  }

  isAutoRefreshRunning(): boolean {
    return false; // Stub implementation
  }

  // Configuration
  getConfig(): AuthClientConfig {
    return { ...this.config };
  }

  dispose(): void {
    this.stopAutoRefresh();
  }

  // Method aliases for test compatibility
  async getTokenWithClientCredentials(scopes?: string[]): Promise<TokenResponse> {
    const result = await this.clientCredentialsAsync(scopes);
    if (!result.success || !result.token) {
      throw new Error(result.error || 'Failed to get token');
    }
    return result.token;
  }

  async getTokenWithJWTBearer(jwtToken: string, scopes?: string[]): Promise<TokenResponse> {
    const result = await this.jwtBearerAsync(jwtToken, scopes);
    if (!result.success || !result.token) {
      throw new Error(result.error || 'Failed to get token');
    }
    return result.token;
  }

  getAuthorizationUrl(scopes?: string[], state?: string, pkceParams?: { challenge: string, method: string } | { code_verifier: string, code_challenge: string, code_challenge_method: string }): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId
    });

    if (this.config.redirectUri) {
      params.append('redirect_uri', this.config.redirectUri);
    }

    if (scopes?.length) {
      params.append('scope', scopes.join(' '));
    } else if (this.config.scopes?.length) {
      params.append('scope', this.config.scopes.join(' '));
    }

    if (state) {
      params.append('state', state);
    }

    if (pkceParams) {
      // Handle both PKCE parameter formats
      if ('challenge' in pkceParams && 'method' in pkceParams) {
        // New format: { challenge, method }
        params.append('code_challenge', pkceParams.challenge);
        params.append('code_challenge_method', pkceParams.method);
      } else if ('code_challenge' in pkceParams && 'code_challenge_method' in pkceParams) {
        // Legacy format: { code_challenge, code_challenge_method }
        params.append('code_challenge', pkceParams.code_challenge);
        params.append('code_challenge_method', pkceParams.code_challenge_method);
      }
    }

    return `${this.config.authorizationUrl}?${params.toString()}`;
  }

  async exchangeCodeForToken(code: string, codeVerifier?: string): Promise<TokenResponse> {
    // Direct implementation instead of calling authorizationCodeAsync
    try {
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: this.config.clientId
      });

      if (this.config.redirectUri) {
        body.append('redirect_uri', this.config.redirectUri);
      }

      if (this.config.clientSecret) {
        body.append('client_secret', this.config.clientSecret);
      }

      if (codeVerifier) {
        body.append('code_verifier', codeVerifier);
      }

      const response = await fetch(this.config.tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: body.toString()
      });

      if (!response.ok) {
        const errorData = await response.json() as AuthError;
        throw new Error(errorData.error || 'Token exchange failed');
      }

      const token = await response.json() as TokenResponse;
      return token;
    } catch (error) {
      throw new Error(error instanceof Error ? error.message : 'Token exchange failed');
    }
  }
}

// Factory class
export class OAuth2AuthClientFactory {
  static create(
    config: AuthClientConfig | Partial<AuthClientConfig>,
    tokenStorage?: OAuth2TokenStorage,
    logger?: OAuth2Logger
  ): OAuth2AuthClient {
    // Handle partial config with discovery URL
    if ('discoveryUrl' in config && config.discoveryUrl && !config.authorizationUrl) {
      const fullConfig: AuthClientConfig = {
        clientId: config.clientId || '',
        authorizationUrl: '', // Will be populated from discovery
        tokenUrl: '', // Will be populated from discovery
        ...config
      };
      return new OAuth2AuthClient(fullConfig, tokenStorage, logger);
    }
    
    return new OAuth2AuthClient(config as AuthClientConfig, tokenStorage, logger);
  }

  static createFromEnvironment(
    tokenStorage?: OAuth2TokenStorage,
    logger?: OAuth2Logger
  ): OAuth2AuthClient {
    const config: Partial<AuthClientConfig> = {
      clientId: process.env.OAUTH2_CLIENT_ID || '',
      authorizationUrl: process.env.OAUTH2_AUTHORIZATION_URL || '',
      tokenUrl: process.env.OAUTH2_TOKEN_URL || ''
    };

    // Add optional properties only if they exist
    if (process.env.OAUTH2_CLIENT_SECRET) {
      config.clientSecret = process.env.OAUTH2_CLIENT_SECRET;
    }
    if (process.env.OAUTH2_INTROSPECTION_URL) {
      config.introspectionUrl = process.env.OAUTH2_INTROSPECTION_URL;
    }
    if (process.env.OAUTH2_REVOCATION_URL) {
      config.revocationUrl = process.env.OAUTH2_REVOCATION_URL;
    }
    if (process.env.OAUTH2_DISCOVERY_URL) {
      config.discoveryUrl = process.env.OAUTH2_DISCOVERY_URL;
    }

    if (!config.clientId || !config.authorizationUrl || !config.tokenUrl) {
      throw new Error('Required OAuth2 environment variables not set');
    }

    return new OAuth2AuthClient(config as AuthClientConfig, tokenStorage, logger);
  }
}

// Export aliases for compatibility
export { OAuth2AuthClient as AuthClient };
export { OAuth2AuthClientFactory as AuthClientFactory };
