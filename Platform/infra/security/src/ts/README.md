# OAuth2 Authentication Client for TypeScript/JavaScript

A comprehensive OAuth2 authentication client library for the CoyoteSense platform, providing secure unit-to-unit communication with full support for all OAuth2 grant types.

## Features

- **Complete OAuth2 Support**: Client Credentials, Authorization Code + PKCE, JWT Bearer, and Refresh Token flows
- **mTLS Support**: Secure mutual TLS authentication via HTTP client configuration
- **Automatic Token Refresh**: Background token renewal with configurable refresh margins
- **Token Storage Abstraction**: Pluggable storage implementations (memory, database, etc.)
- **Comprehensive Logging**: Configurable logging with multiple implementations
- **TypeScript First**: Full TypeScript support with comprehensive type definitions
- **Modern JavaScript**: ES2020+ with async/await support
- **Web & Node.js**: Compatible with both browser and Node.js environments
- **Factory Pattern**: Easy client creation with fluent builder API
- **Error Handling**: Detailed error responses and exception handling

## Installation

```bash
npm install @coyotesense/oauth2-client-ts
```

## Quick Start

### Client Credentials Flow

```typescript
import { OAuth2AuthClientFactory } from '@coyotesense/oauth2-client-ts';
import { createClient } from '@coyotesense/http-client-ts';

// Create HTTP client
const httpClient = createClient();

// Create OAuth2 client
const client = OAuth2AuthClientFactory.createClientCredentials(
  'https://auth.coyotesense.io',
  'my-client-id',
  'my-client-secret',
  ['read', 'write'],
  httpClient
);

// Authenticate
const result = await client.clientCredentialsAsync();

if (result.success && result.token) {
  console.log('Access Token:', result.token.accessToken);
  console.log('Expires At:', new Date(result.token.expiresAt * 1000));
} else {
  console.error('Authentication failed:', result.error);
}

// Clean up
client.dispose();
```

### Authorization Code Flow with PKCE

```typescript
// Create client for public application
const client = OAuth2AuthClientFactory.createAuthorizationCode(
  'https://auth.coyotesense.io',
  'my-web-app-client',
  ['profile', 'read'],
  httpClient
);

// Step 1: Get authorization URL
const { authorizationUrl, pkceData } = client.startAuthorizationCodeFlow(
  'https://myapp.com/callback',
  ['profile', 'read'],
  'random-state',
  true // Use PKCE
);

// Redirect user to authorizationUrl
console.log('Redirect to:', authorizationUrl);

// Step 2: Handle callback (after user authorization)
const authCode = 'received-from-callback';
const result = await client.completeAuthorizationCodeFlow(
  authCode,
  'https://myapp.com/callback',
  pkceData
);

if (result.success) {
  console.log('User authenticated successfully!');
}
```

### JWT Bearer Flow

```typescript
const client = OAuth2AuthClientFactory.create()
  .serverUrl('https://auth.coyotesense.io')
  .clientCredentials('my-jwt-client')
  .defaultScopes(['read', 'admin'])
  .build(httpClient);

const jwtAssertion = 'your-jwt-token-here';
const result = await client.jwtBearerAsync(jwtAssertion);

if (result.success) {
  console.log('JWT Bearer authentication successful!');
}
```

## Advanced Configuration

### Custom Storage and Logging

```typescript
import { 
  OAuth2AuthClientFactory, 
  MemoryOAuth2TokenStorage, 
  ConsoleOAuth2Logger 
} from '@coyotesense/oauth2-client-ts';

// Custom token storage
class DatabaseTokenStorage extends OAuth2TokenStorage {
  async storeTokenAsync(key: string, token: OAuth2Token): Promise<void> {
    // Store in database
    await database.tokens.save({ key, token });
  }

  async retrieveTokenAsync(key: string): Promise<OAuth2Token | null> {
    // Retrieve from database
    const record = await database.tokens.findByKey(key);
    return record?.token || null;
  }

  // ... implement other methods
}

// Create client with custom configuration
const client = OAuth2AuthClientFactory.create()
  .serverUrl('https://auth.coyotesense.io')
  .clientCredentials('my-client', 'my-secret')
  .defaultScopes(['read', 'write'])
  .timeout(45000)
  .customHeaders({
    'User-Agent': 'MyApp/1.0',
    'X-Request-ID': 'unique-request-id'
  })
  .autoRefresh(true, 300, 60000) // Refresh 5min before expiry, check every 1min
  .tokenStorage(new DatabaseTokenStorage())
  .logger(new ConsoleOAuth2Logger('[MyApp]'))
  .build(httpClient);
```

### Token Management

```typescript
// Check if we have a valid token
const hasValidToken = await client.hasValidTokenAsync();

// Get stored token
const token = await client.getStoredTokenAsync();

// Manual token refresh
if (token?.refreshToken) {
  const refreshResult = await client.refreshTokenAsync(token.refreshToken);
}

// Remove stored token
await client.removeStoredTokenAsync();
```

### Token Introspection and Revocation

```typescript
// Introspect token
const introspectResult = await client.introspectTokenAsync(
  'access-token-to-check',
  'access_token'
);

console.log('Token active:', introspectResult.active);
console.log('Token scopes:', introspectResult.scope);

// Revoke token
const revokeSuccess = await client.revokeTokenAsync(
  'token-to-revoke',
  'access_token'
);
```

## mTLS Configuration

The OAuth2 client supports mTLS (mutual TLS) authentication through the underlying HTTP client:

```typescript
import { createClient, HttpClientConfig } from '@coyotesense/http-client-ts';

// Configure HTTP client with mTLS certificates
const httpConfig: HttpClientConfig = {
  // mTLS configuration would be set here
  // This depends on the specific HTTP client implementation
};

const httpClient = createClient(httpConfig);

const client = OAuth2AuthClientFactory.create()
  .serverUrl('https://auth.coyotesense.io')
  .clientCredentials('mtls-client')
  .build(httpClient);

// All requests will now use mTLS
const result = await client.clientCredentialsAsync();
```

## Error Handling

```typescript
try {
  const result = await client.clientCredentialsAsync();
  
  if (result.success && result.token) {
    // Success case
    console.log('Token received:', result.token.accessToken);
  } else {
    // OAuth2 error
    console.error('OAuth2 Error:', result.error);
    console.error('Description:', result.errorDescription);
    
    // Handle specific errors
    switch (result.error) {
      case 'invalid_client':
        console.error('Invalid client credentials');
        break;
      case 'invalid_scope':
        console.error('Requested scope not available');
        break;
      case 'server_error':
        console.error('Server error, try again later');
        break;
    }
  }
} catch (error) {
  // Network or other errors
  console.error('Request failed:', error);
}
```

## Server Discovery

```typescript
// Discover OAuth2 server capabilities
const serverInfo = await client.discoverServerAsync();

console.log('Supported grant types:', serverInfo.grantTypesSupported);
console.log('Supported scopes:', serverInfo.scopesSupported);
console.log('Authorization endpoint:', serverInfo.authorizationEndpoint);
```

## Testing

The library includes comprehensive test utilities:

```typescript
import { MockHttpClient } from '@coyotesense/http-client-ts';

// Create mock HTTP client for testing
const mockHttpClient = new MockHttpClient();

// Configure mock responses
mockHttpClient.setPredefinedJsonResponse('/oauth2/token', {
  access_token: 'mock-token',
  token_type: 'Bearer',
  expires_in: 3600
});

// Create client with mock HTTP client
const client = OAuth2AuthClientFactory.create()
  .serverUrl('https://mock-auth-server.test')
  .clientCredentials('test-client', 'test-secret')
  .build(mockHttpClient);

// Test authentication
const result = await client.clientCredentialsAsync();
expect(result.success).toBe(true);
```

## Examples

Comprehensive examples are available in the [examples file](./oauth2-client-examples.ts):

- Client Credentials Flow
- JWT Bearer Flow  
- Authorization Code + PKCE Flow
- Token Management and Auto-Refresh
- Token Introspection and Revocation
- Server Discovery
- Advanced Configuration
- Web Application Integration

Run examples:

```bash
npm run examples
```

## API Reference

### OAuth2AuthClient

Main client class implementing all OAuth2 flows.

#### Methods

- `clientCredentialsAsync(scopes?: string[]): Promise<OAuth2AuthResult>`
- `jwtBearerAsync(assertion: string, scopes?: string[]): Promise<OAuth2AuthResult>`
- `startAuthorizationCodeFlow(redirectUri: string, scopes?: string[], state?: string, usePKCE?: boolean)`
- `completeAuthorizationCodeFlow(code: string, redirectUri: string, pkceData?: OAuth2PKCEData): Promise<OAuth2AuthResult>`
- `refreshTokenAsync(refreshToken: string, scopes?: string[]): Promise<OAuth2AuthResult>`
- `getStoredTokenAsync(): Promise<OAuth2Token | null>`
- `storeTokenAsync(token: OAuth2Token): Promise<void>`
- `removeStoredTokenAsync(): Promise<void>`
- `hasValidTokenAsync(marginSeconds?: number): Promise<boolean>`
- `introspectTokenAsync(token: string, tokenTypeHint?: string): Promise<OAuth2IntrospectResponse>`
- `revokeTokenAsync(token: string, tokenTypeHint?: string): Promise<boolean>`
- `discoverServerAsync(): Promise<OAuth2ServerInfo>`
- `startAutoRefresh(): void`
- `stopAutoRefresh(): void`
- `dispose(): void`

### OAuth2AuthClientFactory

Factory class for creating OAuth2 clients with fluent API.

#### Methods

- `static create(): OAuth2AuthClientBuilder`
- `static createSimple(serverUrl: string, clientId: string, clientSecret?: string, httpClient?: CoyoteHttpClient): OAuth2AuthClient`
- `static createClientCredentials(serverUrl: string, clientId: string, clientSecret: string, scopes?: string[], httpClient?: CoyoteHttpClient): OAuth2AuthClient`
- `static createAuthorizationCode(serverUrl: string, clientId: string, scopes?: string[], httpClient?: CoyoteHttpClient): OAuth2AuthClient`

### Types

#### OAuth2ClientConfig

```typescript
interface OAuth2ClientConfig {
  serverUrl: string;
  clientId: string;
  clientSecret?: string;
  defaultScopes?: string[];
  timeoutMs?: number;
  customHeaders?: Record<string, string>;
  enableAutoRefresh?: boolean;
  refreshMarginSeconds?: number;
  refreshCheckIntervalMs?: number;
}
```

#### OAuth2Token

```typescript
interface OAuth2Token {
  accessToken: string;
  tokenType: string;
  expiresAt: number;
  refreshToken?: string;
  scopes?: string[];
  idToken?: string;
}
```

#### OAuth2AuthResult

```typescript
interface OAuth2AuthResult {
  success: boolean;
  token?: OAuth2Token;
  error?: string;
  errorDescription?: string;
  serverInfo?: OAuth2ServerInfo;
}
```

## Browser Support

The library supports modern browsers with the following features:

- ES2020+ (async/await, optional chaining, nullish coalescing)
- Fetch API or polyfill
- Web Crypto API (for PKCE with S256, falls back to plain method)
- Local Storage (for token storage, if using browser storage implementation)

For older browsers, consider using appropriate polyfills.

## Node.js Support

Requires Node.js 18+ with:

- Native fetch support (Node.js 18+)
- Crypto module for PKCE
- File system access (for file-based token storage)

## Security Considerations

1. **Token Storage**: Store tokens securely using appropriate storage mechanisms
2. **HTTPS Only**: Always use HTTPS for OAuth2 endpoints
3. **PKCE**: Always use PKCE for Authorization Code flow
4. **Client Secrets**: Keep client secrets secure and never expose in client-side code
5. **Token Expiration**: Respect token expiration times and refresh appropriately
6. **Scope Limitation**: Request only necessary scopes
7. **State Parameter**: Always use state parameter to prevent CSRF attacks

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

For support and questions:

- GitHub Issues: [Create an issue](https://github.com/coyotesense/coyote-sense-platform/issues)
- Documentation: [CoyoteSense Docs](https://docs.coyotesense.io)
- Email: support@coyotesense.io
