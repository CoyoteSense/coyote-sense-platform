/**
 * OAuth2 Authentication Client - Main Export File
 */

// Export everything from the main implementation
export * from './impl/oauth2-client';
export * from './interfaces/auth-interfaces';

// Export specific classes with aliases for compatibility
export { OAuth2AuthClient as AuthClient, OAuth2AuthClientFactory as AuthClientFactory } from './impl/oauth2-client';

// Default exports for convenience
export { OAuth2AuthClient as default } from './impl/oauth2-client';
