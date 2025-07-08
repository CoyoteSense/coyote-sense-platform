/**
 * OAuth2 Authentication Interfaces for TypeScript/JavaScript
 * 
 * This module contains all the interface definitions and types for OAuth2 authentication
 * in the CoyoteSense platform, supporting multiple OAuth2 flows and authentication methods.
 */

// Authentication Modes
export enum AuthMode {
  ClientCredentials = 'client_credentials',
  ClientCredentialsMtls = 'client_credentials_mtls', 
  JwtBearer = 'jwt_bearer',
  AuthorizationCode = 'authorization_code',
  AuthorizationCodePkce = 'authorization_code_pkce'
}

// Configuration interfaces
export interface AuthClientConfig {
  clientId: string;
  clientSecret?: string;
  authorizationUrl: string;
  tokenUrl: string;
  introspectionUrl?: string;
  revocationUrl?: string;
  discoveryUrl?: string;
  scopes?: string[];
  redirectUri?: string;
  enableAutoRefresh?: boolean;
  tokenRefreshThresholdSeconds?: number;
  maxRetryAttempts?: number;
  retryDelayMs?: number;
  requestTimeoutMs?: number;
  enableServerDiscovery?: boolean;
}

// Token response interfaces
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
}

export interface AuthTokenResponse extends TokenResponse {}

export interface IntrospectResponse {
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

export interface AuthIntrospectResponse extends IntrospectResponse {}

export interface ServerDiscoveryResponse {
  issuer?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  introspection_endpoint?: string;
  revocation_endpoint?: string;
  jwks_uri?: string;
  grant_types_supported?: string[];
  response_types_supported?: string[];
  scopes_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  code_challenge_methods_supported?: string[];
}

// PKCE interface
export interface PKCEParams {
  challenge: string;
  method: string;
  code_verifier?: string;
  code_challenge?: string;
  code_challenge_method?: string;
}

// Error interface
export interface AuthError {
  error: string;
  error_description?: string;
  error_uri?: string;
}

// Storage interface
export interface OAuth2TokenStorage {
  getToken(key: string): Promise<string | null>;
  setToken(key: string, token: string): Promise<void>;
  removeToken(key: string): Promise<void>;
  clear(): Promise<void>;
}

// Logger interface
export interface OAuth2Logger {
  debug(message: string, data?: any): void;
  info(message: string, data?: any): void;
  warn(message: string, data?: any): void;
  error(message: string, data?: any): void;
}

// Storage interface (for compatibility)
export interface AuthTokenStorage extends OAuth2TokenStorage {}

// Logger interface (for compatibility) 
export interface AuthLogger extends OAuth2Logger {}

// Legacy type aliases for backwards compatibility
export type OAuth2Config = AuthClientConfig;
export type OAuth2TokenResponse = TokenResponse;
export type OAuth2TokenIntrospectionResponse = IntrospectResponse;
export type OAuth2ServerDiscoveryResponse = ServerDiscoveryResponse;
