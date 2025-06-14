/**
 * Authentication Client Examples for TypeScript/JavaScript
 * 
 * This file demonstrates how to use the AuthClient for various authentication scenarios
 * in the CoyoteSense platform, including OAuth2, JWT Bearer, and mTLS flows.
 */

import { 
  AuthResult, 
  AuthToken,
  AuthClientConfig,
  AuthPKCEData,
  ConsoleAuthLogger,
  NullAuthLogger,
  MemoryAuthTokenStorage
} from '../../interfaces/ts/auth-interfaces';
import { 
  AuthClientFactory 
} from '../../factory/ts/auth-client-factory';
import { 
  AuthClient
} from '../../clients/typescript/auth-client';
import { CoyoteHttpClient } from '../../../http/ts';

// Example HTTP client creation (replace with actual HTTP client factory)
async function createClient(): Promise<CoyoteHttpClient> {
  // This would use the actual HTTP client factory from the CoyoteSense platform
  // For demonstration purposes, we'll assume it's available
  const { createClient } = await import('../../../http/ts');
  return createClient();
}

/**
 * Example 1: Client Credentials Flow
 * Used for server-to-server authentication where no user interaction is required.
 */
export async function clientCredentialsExample(): Promise<void> {
  console.log('=== Client Credentials Flow Example ===');
  
  try {
    const httpClient = await createClient();
    
    // Create Auth client using factory
    const client = AuthClientFactory.createClientCredentials(
      'https://auth.coyotesense.io',
      'my-service-client',
      'my-client-secret',
      ['read', 'write'],
      httpClient
    );

    // Request access token
    const result = await client.requestToken();
    if (result.success) {
      console.log('✓ Client Credentials authentication successful');
      console.log(`Access Token: ${result.token?.access_token.substring(0, 20)}...`);
      console.log(`Expires in: ${result.token?.expires_in} seconds`);
      
      // Use the token for authenticated requests
      await makeAuthenticatedRequest(result.token!.access_token);
    } else {
      console.error('✗ Client Credentials authentication failed:', result.error);
    }
  } catch (error) {
    console.error('✗ Client Credentials example failed:', error);
  }
}

/**
 * Example 2: JWT Bearer Assertion Flow
 * Used for service-to-service authentication using signed JWT assertions.
 */
export async function jwtBearerExample(): Promise<void> {
  console.log('=== JWT Bearer Assertion Flow Example ===');
  
  try {
    const httpClient = await createClient();
    
    // Create Auth client with JWT Bearer configuration
    const client = AuthClientFactory.create()
      .withEndpoint('https://auth.coyotesense.io')
      .withJwtBearer(
        'unit-12345',                    // Unit ID as issuer
        './certs/unit-private-key.pem',  // Private key for signing
        'key-id-123'                     // Key identifier
      )
      .withScopes(['trading', 'market-data'])
      .withHttpClient(httpClient)
      .logger(new ConsoleAuthLogger('[JWT-Example]'))
      .build();

    // Request access token using JWT assertion
    const result = await client.requestTokenWithJWT();
    if (result.success) {
      console.log('✓ JWT Bearer authentication successful');
      console.log(`Access Token: ${result.token?.access_token.substring(0, 20)}...`);
      
      // Store token for later use
      const tokenStorage = new MemoryAuthTokenStorage();
      await tokenStorage.store('unit-12345', result.token!);
      
    } else {
      console.error('✗ JWT Bearer authentication failed:', result.error);
    }
  } catch (error) {
    console.error('✗ JWT Bearer example failed:', error);
  }
}

/**
 * Example 3: Authorization Code Flow with PKCE
 * Used for web applications and mobile apps where user consent is required.
 */
export async function authorizationCodeWithPKCEExample(): Promise<void> {
  console.log('=== Authorization Code + PKCE Flow Example ===');
  
  try {
    const httpClient = await createClient();
    
    // Create Auth client for public client (no client secret)
    const client = AuthClientFactory.createAuthorizationCode(
      'https://auth.coyotesense.io',
      'my-web-app',
      ['read', 'write', 'profile'],
      httpClient
    );

    const redirectUri = 'https://myapp.example.com/oauth/callback';
    
    // Step 1: Start authorization flow and get authorization URL
    const { authorizationUrl, pkceData } = client.startAuthorizationCodeFlow(
      redirectUri,
      ['read', 'write', 'profile'],
      'random-state-123',
      true // Use PKCE
    );
    
    console.log('📋 Authorization URL:', authorizationUrl);
    console.log('🔐 PKCE Code Challenge:', pkceData?.codeChallenge);
    
    // Step 2: User would be redirected to authorization server and back
    // For this example, we'll simulate receiving an authorization code
    const simulatedAuthCode = 'simulated-auth-code-12345';
    
    console.log('⏳ Simulating user authorization...');
    
    // Step 3: Exchange authorization code for access token
    const result = await client.completeAuthorizationCodeFlow(
      simulatedAuthCode,
      redirectUri,
      pkceData
    );
    
    if (result.success && result.token) {
      console.log('✅ Authorization Code flow successful!');
      console.log(`Access Token: ${result.token.accessToken.substring(0, 20)}...`);
      console.log(`Refresh Token: ${result.token.refreshToken ? 'Present' : 'Not available'}`);
      console.log(`Scopes: ${result.token.scopes?.join(', ')}`);
      
      // Demonstrate token refresh if refresh token is available
      if (result.token.refreshToken) {
        await demonstrateTokenRefresh(client, result.token.refreshToken);
      }
    } else {
      console.error('❌ Authorization Code flow failed:', result.error, result.errorDescription);
    }

    client.dispose();
  } catch (error) {
    console.error('❌ Authorization Code example failed:', error);
  }
}

/**
 * Example 4: Token Management and Auto-Refresh
 * Demonstrates token storage, retrieval, and automatic refresh capabilities.
 */
export async function tokenManagementExample(): Promise<void> {
  console.log('=== Token Management and Auto-Refresh Example ===');
  
  try {
    const httpClient = await createClient();
    
    // Create custom token storage for demonstration
    const tokenStorage = new MemoryOAuth2TokenStorage();
    
    // Create Auth client with custom configuration
    const client = AuthClientFactory.create()
      .withEndpoint('https://auth.coyotesense.io')
      .withClientCredentials('my-auto-refresh-client', 'my-secret')
      .withScopes(['read', 'write'])
      .autoRefresh(true, 60, 30000) // Auto-refresh 60s before expiry, check every 30s
      .withTokenStorage(tokenStorage)
      .logger(new ConsoleAuthLogger('[AutoRefresh]'))
      .build(httpClient);

    // Get initial token
    console.log('🔑 Getting initial access token...');
    const result = await client.requestToken();
    
    if (result.success) {
      console.log('✅ Initial token obtained');
      
      // Check if we have a valid stored token
      const hasValidToken = await client.hasValidTokenAsync();
      console.log(`📋 Has valid token: ${hasValidToken}`);
      
      // Retrieve stored token
      const storedToken = await client.getStoredTokenAsync();
      if (storedToken) {
        console.log(`💾 Stored token expires at: ${new Date(storedToken.expiresAt * 1000)}`);
      }
      
      // Demonstrate manual token refresh
      if (result.token.refreshToken) {
        console.log('🔄 Demonstrating manual token refresh...');
        const refreshResult = await client.refreshTokenAsync(result.token.refreshToken);
        
        if (refreshResult.success) {
          console.log('✅ Token refresh successful');
        } else {
          console.log('❌ Token refresh failed:', refreshResult.error);
        }
      }
      
      // Auto-refresh is already started by default
      console.log('⏰ Auto-refresh is running in the background');
      
      // Simulate some time passing and demonstrate token validation
      setTimeout(async () => {
        const stillValid = await client.hasValidTokenAsync();
        console.log(`📋 Token still valid after delay: ${stillValid}`);
      }, 5000);
    }

    // Note: In a real application, you would keep the client alive
    // For this example, we'll dispose after a short delay
    setTimeout(() => {
      client.dispose();
      console.log('🧹 Client disposed');
    }, 10000);
    
  } catch (error) {
    console.error('❌ Token management example failed:', error);
  }
}

/**
 * Example 5: Token Introspection and Revocation
 * Demonstrates how to check token validity and revoke tokens.
 */
export async function tokenIntrospectionExample(): Promise<void> {
  console.log('=== Token Introspection and Revocation Example ===');
  
  try {
    const httpClient = await createClient();
    
    const client = AuthClientFactory.createClientCredentials(
      'https://auth.coyotesense.io',
      'my-introspection-client',
      'my-secret',
      ['read'],
      httpClient
    );

    // Get a token first
    const tokenResult = await client.clientCredentialsAsync();
    
    if (tokenResult.success && tokenResult.token) {
      const accessToken = tokenResult.token.accessToken;
      
      // Introspect the token
      console.log('🔍 Introspecting access token...');
      const introspectResult = await client.introspectTokenAsync(accessToken, 'access_token');
      
      console.log('📋 Token introspection result:');
      console.log(`  Active: ${introspectResult.active}`);
      console.log(`  Client ID: ${introspectResult.client_id}`);
      console.log(`  Scopes: ${introspectResult.scope}`);
      console.log(`  Expires at: ${introspectResult.exp ? new Date(introspectResult.exp * 1000) : 'N/A'}`);
      
      // Revoke the token
      console.log('🗑️ Revoking access token...');
      const revokeSuccess = await client.revokeTokenAsync(accessToken, 'access_token');
      
      if (revokeSuccess) {
        console.log('✅ Token revoked successfully');
        
        // Introspect again to verify revocation
        const postRevokeIntrospect = await client.introspectTokenAsync(accessToken, 'access_token');
        console.log(`📋 Token active after revocation: ${postRevokeIntrospect.active}`);
      } else {
        console.error('❌ Token revocation failed');
      }
    }

    client.dispose();
  } catch (error) {
    console.error('❌ Token introspection example failed:', error);
  }
}

/**
 * Example 6: Server Discovery
 * Demonstrates discovering OAuth2 server capabilities.
 */
export async function serverDiscoveryExample(): Promise<void> {
  console.log('=== Server Discovery Example ===');
  
  try {
    const httpClient = await createClient();
    
    const client = AuthClientFactory.create()
      .withEndpoint('https://auth.coyotesense.io')
      .withClientCredentials('discovery-client')
      .build(httpClient);

    // Discover server capabilities
    console.log('🔍 Discovering OAuth2 server capabilities...');
    const serverInfo = await client.discoverServerAsync();
    
    console.log('📋 Server Discovery Results:');
    console.log(`  Issuer: ${serverInfo.issuer}`);
    console.log(`  Authorization Endpoint: ${serverInfo.authorizationEndpoint}`);
    console.log(`  Token Endpoint: ${serverInfo.tokenEndpoint}`);
    console.log(`  Supported Grant Types: ${serverInfo.grantTypesSupported?.join(', ')}`);
    console.log(`  Supported Scopes: ${serverInfo.scopesSupported?.join(', ')}`);

    client.dispose();
  } catch (error) {
    console.error('❌ Server discovery example failed:', error);
  }
}

/**
 * Example 7: Custom Configuration and Error Handling
 * Demonstrates advanced configuration options and comprehensive error handling.
 */
export async function advancedConfigurationExample(): Promise<void> {
  console.log('=== Advanced Configuration Example ===');
  
  try {
    const httpClient = await createClient();
    
    // Create client with advanced configuration
    const client = AuthClientFactory.create()
      .withEndpoint('https://auth.coyotesense.io')
      .withClientCredentials('advanced-client', 'advanced-secret')
      .withScopes(['read', 'write', 'admin'])
      .timeout(45000) // 45 second timeout
      .customHeaders({
        'User-Agent': 'CoyoteSense-OAuth2-Client/1.0',
        'X-Request-ID': 'example-request-' + Date.now()
      })
      .autoRefresh(true, 120, 45000) // Refresh 2 minutes before expiry, check every 45s
      .logger(new ConsoleAuthLogger('[Advanced]'))
      .build(httpClient);

    // Attempt authentication with error handling
    console.log('🔑 Attempting authentication with advanced configuration...');
    
    try {
      const result = await client.clientCredentialsAsync(['read', 'write']);
      
      if (result.success && result.token) {
        console.log('✅ Advanced authentication successful');
        console.log(`📋 Configuration used: ${JSON.stringify(client.getConfig(), null, 2)}`);
        
        // Demonstrate making multiple concurrent requests
        await demonstrateConcurrentRequests(client);
      } else {
        console.error('❌ Authentication failed with advanced config:');
        console.error(`   Error: ${result.error}`);
        console.error(`   Description: ${result.errorDescription}`);
      }
    } catch (error) {
      console.error('❌ Authentication exception:', error);
    }

    client.dispose();
  } catch (error) {
    console.error('❌ Advanced configuration example failed:', error);
  }
}

/**
 * Example 8: Web Application Integration
 * Shows how to integrate OAuth2 client in a web application context.
 */
export async function webApplicationExample(): Promise<void> {
  console.log('=== Web Application Integration Example ===');
  
  try {
    const httpClient = await createClient();
    
    // Configuration for a web application
    const client = AuthClientFactory.create()
      .withEndpoint('https://auth.coyotesense.io')
      .withClientCredentials('web-app-client') // Public client, no secret
      .withScopes(['profile', 'read'])
      .autoRefresh(false) // Handle refresh manually in web context
      .logger(new NullAuthLogger()) // Silent logging for production
      .build(httpClient);

    // Simulate web application flow
    console.log('🌐 Starting web application OAuth2 flow...');
    
    // Generate authorization URL for user redirect
    const { authorizationUrl, pkceData } = client.startAuthorizationCodeFlow(
      'https://mywebapp.example.com/auth/callback',
      ['profile', 'read'],
      'webapp-state-' + Date.now(),
      true // Always use PKCE for web apps
    );
    
    console.log('📋 Generated authorization URL:');
    console.log(`   ${authorizationUrl}`);
    console.log('📋 Store PKCE data in session:', {
      codeVerifier: pkceData?.codeVerifier?.substring(0, 10) + '...',
      state: pkceData?.state
    });
    
    // Simulate callback handling (this would happen after user authorization)
    console.log('⏳ Simulating authorization callback...');
    
    const simulatedCallbackCode = 'webapp-auth-code-' + Date.now();
    const result = await client.completeAuthorizationCodeFlow(
      simulatedCallbackCode,
      'https://mywebapp.example.com/auth/callback',
      pkceData
    );
    
    if (result.success && result.token) {
      console.log('✅ Web application authentication successful');
      console.log(`📋 User authenticated with scopes: ${result.token.scopes?.join(', ')}`);
      
      // Store token in secure storage (not shown here)
      console.log('💾 Store token securely in user session or database');
    } else {
      console.error('❌ Web application authentication failed:', result.error);
    }

    client.dispose();
  } catch (error) {
    console.error('❌ Web application example failed:', error);
  }
}

// Helper functions

async function createJWTAssertion(): Promise<string> {
  // In a real implementation, this would create a proper JWT
  // For demo purposes, return a mock JWT-like string
  return 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteS1qd3QtaXNzdWVyIiwic3ViIjoidXNlci0xMjMiLCJhdWQiOiJhdXRoLmNveW90ZXNlbnNlLmlvIiwiZXhwIjoxNjk5OTk5OTk5LCJpYXQiOjE2OTk5OTk5OTksInNjb3BlIjoicmVhZCBhZG1pbiJ9.mock-signature';
}

async function makeAuthenticatedRequest(accessToken: string): Promise<void> {
  console.log('🌐 Making authenticated API call...');
  
  try {
    const httpClient = await createClient();
    const response = await httpClient.getAsync('/api/user/profile', {
      'Authorization': `Bearer ${accessToken}`
    });
    
    if (response.isSuccess) {
      console.log('✅ API call successful');
      console.log(`📋 Response: ${response.body.substring(0, 100)}...`);
    } else {
      console.error('❌ API call failed:', response.statusCode, response.errorMessage);
    }
  } catch (error) {
    console.error('❌ API call exception:', error);
  }
}

async function demonstrateTokenRefresh(client: AuthClient, refreshToken: string): Promise<void> {
  console.log('🔄 Demonstrating token refresh...');
  
  try {
    const refreshResult = await client.refreshTokenAsync(refreshToken);
    
    if (refreshResult.success && refreshResult.token) {
      console.log('✅ Token refresh successful');
      console.log(`📋 New token expires at: ${new Date(refreshResult.token.expiresAt * 1000)}`);
    } else {
      console.error('❌ Token refresh failed:', refreshResult.error);
    }
  } catch (error) {
    console.error('❌ Token refresh exception:', error);
  }
}

async function demonstrateConcurrentRequests(client: AuthClient): Promise<void> {
  console.log('⚡ Demonstrating concurrent token requests...');
  
  const promises = [
    client.clientCredentialsAsync(['read']),
    client.clientCredentialsAsync(['write']),
    client.clientCredentialsAsync(['admin'])
  ];
  
  try {
    const results = await Promise.all(promises);
    const successCount = results.filter(r => r.success).length;
    
    console.log(`📋 Concurrent requests completed: ${successCount}/${results.length} successful`);
  } catch (error) {
    console.error('❌ Concurrent requests failed:', error);
  }
}

// Main function to run all examples
export async function runAllExamples(): Promise<void> {
  console.log('🚀 Starting Auth Client Examples');
  console.log('===================================');
  
  const examples = [
    { name: 'Client Credentials', fn: clientCredentialsExample },
    { name: 'JWT Bearer', fn: jwtBearerExample },
    { name: 'Authorization Code + PKCE', fn: authorizationCodeWithPKCEExample },
    { name: 'Token Management', fn: tokenManagementExample },
    { name: 'Token Introspection', fn: tokenIntrospectionExample },
    { name: 'Server Discovery', fn: serverDiscoveryExample },
    { name: 'Advanced Configuration', fn: advancedConfigurationExample },
    { name: 'Web Application', fn: webApplicationExample }
  ];
  
  for (const example of examples) {
    console.log(`\n📖 Running ${example.name} Example...`);
    try {
      await example.fn();
      console.log(`✅ ${example.name} example completed`);
    } catch (error) {
      console.error(`❌ ${example.name} example failed:`, error);
    }
    
    // Small delay between examples
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  console.log('\n🎉 All Auth examples completed!');
}

// Export individual examples for selective usage
export {
  clientCredentialsExample,
  jwtBearerExample,
  authorizationCodeWithPKCEExample,
  tokenManagementExample,
  tokenIntrospectionExample,
  serverDiscoveryExample,
  advancedConfigurationExample,
  webApplicationExample
};

// If running as main module, execute all examples
if (typeof require !== 'undefined' && require.main === module) {
  runAllExamples().catch(console.error);
}
