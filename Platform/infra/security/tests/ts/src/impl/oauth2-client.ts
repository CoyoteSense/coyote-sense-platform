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

// For Node.js environments, we need to handle Buffer
const getBuffer = (): typeof Buffer => {
  try {
    return Buffer;
  } catch {
    // Fallback for environments without Buffer
    return {
      from: (str: string, encoding: BufferEncoding = 'utf8') => {
        if (encoding === 'base64url') {
          // Convert base64url to base64
          const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
          const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
          return {
            toString: () => atob(padded)
          };
        }
        return {
          toString: () => str
        };
      }
    } as any;
  }
};

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
    // Validate configuration
    if (!config.clientId || config.clientId.trim() === '') {
      throw new Error('Client ID is required');
    }

    if (!config.tokenUrl) {
      throw new Error('Token URL is required');
    }

    try {
      new URL(config.tokenUrl);
    } catch {
      throw new Error('Invalid token URL');
    }

    if (config.redirectUri) {
      try {
        new URL(config.redirectUri);
      } catch {
        throw new Error('Invalid redirect URI');
      }
    }

    if (config.requestTimeoutMs !== undefined && config.requestTimeoutMs <= 0) {
      throw new Error('Request timeout must be positive');
    }

    if (config.maxRetryAttempts !== undefined && config.maxRetryAttempts < 0) {
      throw new Error('Max retry attempts must be non-negative');
    }

    this.config = config;
    this.tokenStorage = tokenStorage;
    this.logger = logger;
  }

  // Client Credentials Flow
  async clientCredentialsAsync(scopes?: string[]): Promise<OAuth2AuthResult> {
    try {
      this.logger?.debug('Starting client credentials flow');
      
      const body = new URLSearchParams();
      body.append('grant_type', 'client_credentials');

      if (scopes?.length) {
        body.append('scope', scopes.join(' '));
      } else if (this.config.scopes?.length) {
        body.append('scope', this.config.scopes.join(' '));
      }

      const headers: Record<string, string> = {
        'Content-Type': 'application/x-www-form-urlencoded'
      };

      // Use Basic Authentication if client secret is provided
      if (this.config.clientSecret) {
        const credentials = btoa(`${this.config.clientId}:${this.config.clientSecret}`);
        headers['Authorization'] = `Basic ${credentials}`;
      } else {
        // Fall back to including client_id in body
        body.append('client_id', this.config.clientId);
      }

      const response = await fetch(this.config.tokenUrl, {
        method: 'POST',
        headers,
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
        if (token.refresh_token) {
          await this.tokenStorage.setToken('refresh_token', token.refresh_token);
        }
      }

      this.logger?.info('Client credentials token obtained');

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
      const body = new URLSearchParams();
      body.append('grant_type', 'refresh_token');
      body.append('refresh_token', refreshToken);

      if (scopes?.length) {
        body.append('scope', scopes.join(' '));
      }

      const headers: Record<string, string> = {
        'Content-Type': 'application/x-www-form-urlencoded'
      };

      // Use Basic Authentication if client secret is provided
      if (this.config.clientSecret) {
        const credentials = btoa(`${this.config.clientId}:${this.config.clientSecret}`);
        headers['Authorization'] = `Basic ${credentials}`;
      } else {
        // Fall back to including client_id in body
        body.append('client_id', this.config.clientId);
      }

      const response = await fetch(this.config.tokenUrl, {
        method: 'POST',
        headers,
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
        if (token.refresh_token) {
          await this.tokenStorage.setToken('refresh_token', token.refresh_token);
        }
      }

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

    const response = await fetch(this.config.discoveryUrl, {
      method: 'GET'
    });
    
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

    // Check if token is a JWT and parse its expiry
    try {
      const payloadPart = token.split('.')[1];
      if (!payloadPart) return true;

      const buffer = getBuffer();
      const payload = JSON.parse(buffer.from(payloadPart, 'base64url').toString());
      const exp = payload.exp;
      
      if (!exp) return true;

      const now = Math.floor(Date.now() / 1000);
      const refreshThreshold = this.config.tokenRefreshThresholdSeconds || 300;
      
      // Return true if token expires within the refresh threshold
      return exp <= (now + refreshThreshold);
    } catch (error) {
      // If we can't parse the token, assume it needs refresh
      return true;
    }
  }

  async getValidAccessToken(): Promise<string> {
    const needsRefresh = await this.needsTokenRefresh();
    if (needsRefresh) {
      // Check if we have a refresh token
      const refreshToken = await this.getStoredRefreshToken();
      if (refreshToken) {
        const tokenResponse = await this.getTokenWithRefreshToken(refreshToken);
        return tokenResponse.access_token;
      } else {
        // Fall back to client credentials
        const tokenResponse = await this.getTokenWithClientCredentials();
        return tokenResponse.access_token;
      }
    }

    const accessToken = await this.getStoredAccessToken();
    if (!accessToken) {
      const tokenResponse = await this.getTokenWithClientCredentials();
      return tokenResponse.access_token;
    }

    return accessToken;
  }

  // Token refresh method
  async getTokenWithRefreshToken(refreshToken: string): Promise<TokenResponse> {
    const result = await this.refreshTokenAsync(refreshToken);
    if (!result.success || !result.token) {
      // Handle different error types with specific message formats
      if (result.error === 'network_error') {
        // For network errors, use the error description directly
        throw new Error(`OAuth2 request failed: ${result.errorDescription}`);
      } else if (result.errorDescription) {
        // For OAuth2 errors, use the standard format
        throw new Error(`OAuth2 request failed: ${result.error} - ${result.errorDescription}`);
      } else {
        throw new Error(`OAuth2 request failed: ${result.error}`);
      }
    }
    return result.token;
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
      // Handle different error types with specific message formats
      if (result.error === 'network_error') {
        // For network errors, use the error description directly
        throw new Error(`OAuth2 request failed: ${result.errorDescription}`);
      } else if (result.errorDescription) {
        // For OAuth2 errors, use the standard format
        throw new Error(`OAuth2 request failed: ${result.error} - ${result.errorDescription}`);
      } else {
        throw new Error(`OAuth2 request failed: ${result.error}`);
      }
    }
    return result.token;
  }

  async getTokenWithJWTBearer(jwtToken: string, scopes?: string[]): Promise<TokenResponse> {
    if (!jwtToken || jwtToken.trim() === '') {
      throw new Error('JWT assertion is required');
    }
    
    const result = await this.jwtBearerAsync(jwtToken, scopes);
    if (!result.success || !result.token) {
      // Handle different error types with specific message formats
      if (result.error === 'network_error') {
        // For network errors, use the error description directly
        throw new Error(`OAuth2 request failed: ${result.errorDescription}`);
      } else if (result.errorDescription) {
        // For OAuth2 errors, use the standard format
        throw new Error(`OAuth2 request failed: ${result.error} - ${result.errorDescription}`);
      } else {
        throw new Error(`OAuth2 request failed: ${result.error}`);
      }
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

    if (!config.clientId) {
      throw new Error('Required environment variable OAUTH2_CLIENT_ID is not set');
    }
    if (!config.authorizationUrl) {
      throw new Error('Required environment variable OAUTH2_AUTHORIZATION_URL is not set');
    }
    if (!config.tokenUrl) {
      throw new Error('Required environment variable OAUTH2_TOKEN_URL is not set');
    }

    return new OAuth2AuthClient(config as AuthClientConfig, tokenStorage, logger);
  }
}

// Export aliases for compatibility
export { OAuth2AuthClient as AuthClient };
export { OAuth2AuthClientFactory as AuthClientFactory };
