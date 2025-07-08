/**
 * OAuth2 Authentication Client Factory for TypeScript/JavaScript
 */

import { 
  AuthClientConfig,
  OAuth2TokenStorage,
  OAuth2Logger
} from '../../interfaces/auth-interfaces';
import { OAuth2AuthClient } from '../../impl/oauth2-client';

// Re-export for test compatibility
export { OAuth2AuthClient as AuthClient } from '../../impl/oauth2-client';

// Export all types and interfaces needed by tests
export {
  AuthClientConfig,
  TokenResponse,
  IntrospectResponse,
  ServerDiscoveryResponse,
  AuthError,
  OAuth2TokenStorage,
  OAuth2Logger,
  AuthMode,
  OAuth2AuthClient,
  OAuth2AuthResult
} from '../../impl/oauth2-client';

export class OAuth2AuthClientFactory {
  static create(
    config: AuthClientConfig,
    tokenStorage?: OAuth2TokenStorage,
    logger?: OAuth2Logger
  ): OAuth2AuthClient {
    return new OAuth2AuthClient(config, tokenStorage, logger);
  }

  static createFromEnvironment(
    tokenStorage?: OAuth2TokenStorage,
    logger?: OAuth2Logger
  ): OAuth2AuthClient {
    const config: AuthClientConfig = {
      clientId: process.env.OAUTH2_CLIENT_ID || '',
      authorizationUrl: process.env.OAUTH2_AUTHORIZATION_URL || '',
      tokenUrl: process.env.OAUTH2_TOKEN_URL || '',
      scopes: process.env.OAUTH2_SCOPES?.split(',') || [],
      enableAutoRefresh: process.env.OAUTH2_ENABLE_AUTO_REFRESH === 'true',
      tokenRefreshThresholdSeconds: parseInt(process.env.OAUTH2_REFRESH_THRESHOLD || '300'),
      maxRetryAttempts: parseInt(process.env.OAUTH2_MAX_RETRY_ATTEMPTS || '3'),
      retryDelayMs: parseInt(process.env.OAUTH2_RETRY_DELAY_MS || '1000'),
      requestTimeoutMs: parseInt(process.env.OAUTH2_REQUEST_TIMEOUT_MS || '10000'),
      enableServerDiscovery: process.env.OAUTH2_ENABLE_SERVER_DISCOVERY === 'true'
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
    if (process.env.OAUTH2_REDIRECT_URI) {
      config.redirectUri = process.env.OAUTH2_REDIRECT_URI;
    }

    if (!config.clientId) {
      throw new Error('OAuth2 client ID is required. Set OAUTH2_CLIENT_ID environment variable.');
    }

    if (!config.authorizationUrl) {
      throw new Error('OAuth2 authorization URL is required. Set OAUTH2_AUTHORIZATION_URL environment variable.');
    }

    if (!config.tokenUrl) {
      throw new Error('OAuth2 token URL is required. Set OAUTH2_TOKEN_URL environment variable.');
    }

    return new OAuth2AuthClient(config, tokenStorage, logger);
  }
}

// Re-export for test compatibility
export { OAuth2AuthClientFactory as AuthClientFactory };
