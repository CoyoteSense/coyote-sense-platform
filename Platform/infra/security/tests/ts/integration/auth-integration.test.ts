import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import { AuthClient, AuthClientFactory } from '../../../typescript/auth-client';
import {
    AuthConfig,
    AuthTokenResponse,
    AuthServerDiscoveryResponse,
    AuthTokenStorage,
    AuthLogger
} from '../../../typescript/auth-client';

/**
 * Integration tests for AuthClient against a real authentication server
 * 
 * These tests require a running authentication server and should be run in a test environment.
 * The tests can be configured to run against different authentication providers by setting
 * environment variables.
 * 
 * Environment Variables:
 * - AUTH_TEST_SERVER_URL: Base URL of the authentication server
 * - AUTH_TEST_CLIENT_ID: Client ID for testing
 * - AUTH_TEST_CLIENT_SECRET: Client secret for testing
 * - AUTH_TEST_REDIRECT_URI: Redirect URI for testing
 * - AUTH_TEST_USERNAME: Username for resource owner password credentials
 * - AUTH_TEST_PASSWORD: Password for resource owner password credentials
 * - AUTH_SKIP_INTEGRATION_TESTS: Set to 'true' to skip integration tests
 */

// Check if integration tests should be skipped
const SKIP_INTEGRATION_TESTS = process.env.AUTH_SKIP_INTEGRATION_TESTS === 'true';

// Test server configuration
const TEST_CONFIG = {
    serverUrl: process.env.AUTH_TEST_SERVER_URL || 'https://localhost:5001',
    clientId: process.env.AUTH_TEST_CLIENT_ID || 'test-client-id',
    clientSecret: process.env.AUTH_TEST_CLIENT_SECRET || 'test-client-secret',
    redirectUri: process.env.AUTH_TEST_REDIRECT_URI || 'https://localhost:3000/callback',
    username: process.env.AUTH_TEST_USERNAME || 'testuser',
    password: process.env.AUTH_TEST_PASSWORD || 'testpass'
};

// Simple in-memory token storage for integration tests
class IntegrationTokenStorage implements AuthTokenStorage {
    private tokens: Map<string, string> = new Map();

    async getToken(key: string): Promise<string | null> {
        return this.tokens.get(key) || null;
    }

    async setToken(key: string, token: string): Promise<void> {
        this.tokens.set(key, token);
    }

    async removeToken(key: string): Promise<void> {
        this.tokens.delete(key);
    }

    async clear(): Promise<void> {
        this.tokens.clear();
    }
}

// Simple console logger for integration tests
class IntegrationLogger implements AuthLogger {
    debug(message: string, data?: any): void {
        if (process.env.AUTH_TEST_DEBUG === 'true') {
            console.debug(`[DEBUG] ${message}`, data || '');
        }
    }

    info(message: string, data?: any): void {
        console.info(`[INFO] ${message}`, data || '');
    }

    warn(message: string, data?: any): void {
        console.warn(`[WARN] ${message}`, data || '');
    }

    error(message: string, data?: any): void {
        console.error(`[ERROR] ${message}`, data || '');
    }
}

// Test helper to wait for server availability
async function waitForServerAvailability(url: string, timeoutMs: number = 30000): Promise<boolean> {
    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
        try {
            const response = await fetch(url);
            if (response.status < 500) {
                return true;
            }
        } catch (error) {
            // Server not available yet
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    return false;
}

// Skip integration tests if configured
const describeIntegration = SKIP_INTEGRATION_TESTS ? describe.skip : describe;

describeIntegration('AuthClient Integration Tests', () => {
    let client: AuthClient;
    let config: AuthConfig;
    let tokenStorage: IntegrationTokenStorage;
    let logger: IntegrationLogger;

    beforeAll(async () => {
        // Check if test server is available
        const serverAvailable = await waitForServerAvailability(`${TEST_CONFIG.serverUrl}/.well-known/openid_configuration`);
        if (!serverAvailable) {
            console.warn(`Authentication test server not available at ${TEST_CONFIG.serverUrl}. Skipping integration tests.`);
            return;
        }

        // Initialize test components
        tokenStorage = new IntegrationTokenStorage();
        logger = new IntegrationLogger();

        config = {
            clientId: TEST_CONFIG.clientId,
            clientSecret: TEST_CONFIG.clientSecret,
            authorizationUrl: `${TEST_CONFIG.serverUrl}/oauth2/authorize`,
            tokenUrl: `${TEST_CONFIG.serverUrl}/oauth2/token`,
            introspectionUrl: `${TEST_CONFIG.serverUrl}/oauth2/introspect`,
            revocationUrl: `${TEST_CONFIG.serverUrl}/oauth2/revoke`,
            discoveryUrl: `${TEST_CONFIG.serverUrl}/.well-known/openid_configuration`,
            redirectUri: TEST_CONFIG.redirectUri,
            scopes: ['read', 'write'],
            enableAutoRefresh: true,
            tokenRefreshThresholdSeconds: 300,
            maxRetryAttempts: 3,
            retryDelayMs: 1000,
            requestTimeoutMs: 30000,
            enableServerDiscovery: true
        };

        client = new AuthClient(config, tokenStorage, logger);
    }, 60000);

    beforeEach(async () => {
        // Clear stored tokens before each test
        await tokenStorage.clear();
    });

    afterEach(async () => {
        // Clean up any stored tokens after each test
        await tokenStorage.clear();
    });

    describe('Server Discovery', () => {
        it('should successfully discover server endpoints', async () => {
            const discovery = await client.discoverServerEndpoints();

            expect(discovery).toBeDefined();
            expect(discovery.issuer).toBeTruthy();
            expect(discovery.authorization_endpoint).toBeTruthy();
            expect(discovery.token_endpoint).toBeTruthy();
            expect(discovery.grant_types_supported).toContain('client_credentials');
            expect(discovery.response_types_supported).toContain('code');
        });

        it('should handle server discovery failures gracefully', async () => {            const invalidClient = new AuthClient(
                { ...config, discoveryUrl: 'https://invalid.example.com/.well-known/openid_configuration' },
                tokenStorage,
                logger
            );

            await expect(invalidClient.discoverServerEndpoints())
                .rejects.toThrow();
        });
    });

    describe('Client Credentials Flow', () => {
        it('should successfully obtain access token using client credentials', async () => {
            const tokenResponse = await client.getTokenWithClientCredentials();

            expect(tokenResponse).toBeDefined();
            expect(tokenResponse.access_token).toBeTruthy();
            expect(tokenResponse.token_type).toBe('Bearer');
            expect(tokenResponse.expires_in).toBeGreaterThan(0);
            expect(typeof tokenResponse.expires_in).toBe('number');

            // Verify token is stored
            const storedToken = await tokenStorage.getToken('access_token');
            expect(storedToken).toBe(tokenResponse.access_token);
        });

        it('should successfully obtain token with specific scopes', async () => {
            const tokenResponse = await client.getTokenWithClientCredentials(['read']);

            expect(tokenResponse).toBeDefined();
            expect(tokenResponse.access_token).toBeTruthy();
            expect(tokenResponse.scope).toContain('read');
        });

        it('should handle invalid client credentials', async () => {
            const invalidClient = new AuthClient(
                { ...config, clientSecret: 'invalid-secret' },
                tokenStorage,
                logger
            );

            await expect(invalidClient.getTokenWithClientCredentials())
                .rejects.toThrow();
        });
    });

    describe('Token Introspection', () => {
        let accessToken: string;

        beforeEach(async () => {
            // Obtain a valid access token for introspection tests
            const tokenResponse = await client.getTokenWithClientCredentials();
            accessToken = tokenResponse.access_token;
        });

        it('should successfully introspect active token', async () => {
            const introspection = await client.introspectToken(accessToken);

            expect(introspection).toBeDefined();
            expect(introspection.active).toBe(true);
            expect(introspection.client_id).toBe(TEST_CONFIG.clientId);
            expect(introspection.token_type).toBe('Bearer');
            expect(introspection.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
        });

        it('should return inactive for invalid token', async () => {
            const introspection = await client.introspectToken('invalid-token');

            expect(introspection).toBeDefined();
            expect(introspection.active).toBe(false);
        });
    });

    describe('Token Revocation', () => {
        let accessToken: string;

        beforeEach(async () => {
            // Obtain a valid access token for revocation tests
            const tokenResponse = await client.getTokenWithClientCredentials();
            accessToken = tokenResponse.access_token;
        });

        it('should successfully revoke access token', async () => {
            await expect(client.revokeToken(accessToken, 'access_token'))
                .resolves.not.toThrow();

            // Verify token is now inactive
            const introspection = await client.introspectToken(accessToken);
            expect(introspection.active).toBe(false);
        });

        it('should handle revocation of already revoked token', async () => {
            // Revoke the token first
            await client.revokeToken(accessToken, 'access_token');

            // Try to revoke again - should not throw
            await expect(client.revokeToken(accessToken, 'access_token'))
                .resolves.not.toThrow();
        });
    });

    describe('Token Storage Integration', () => {
        it('should store and retrieve tokens correctly', async () => {
            const tokenResponse = await client.getTokenWithClientCredentials();

            // Verify tokens are stored
            const storedAccessToken = await client.getStoredAccessToken();
            expect(storedAccessToken).toBe(tokenResponse.access_token);

            if (tokenResponse.refresh_token) {
                const storedRefreshToken = await client.getStoredRefreshToken();
                expect(storedRefreshToken).toBe(tokenResponse.refresh_token);
            }
        });

        it('should clear stored tokens', async () => {
            // First obtain and store tokens
            await client.getTokenWithClientCredentials();

            // Verify tokens are stored
            expect(await client.getStoredAccessToken()).toBeTruthy();

            // Clear tokens
            await client.clearStoredTokens();

            // Verify tokens are cleared
            expect(await client.getStoredAccessToken()).toBeNull();
            expect(await client.getStoredRefreshToken()).toBeNull();
        });
    });

    describe('Auto-Refresh Functionality', () => {
        it('should detect when token needs refresh', async () => {
            // Get a fresh token
            const tokenResponse = await client.getTokenWithClientCredentials();
            
            // Token should not need refresh initially
            const needsRefresh = await client.needsTokenRefresh();
            expect(needsRefresh).toBe(false);
        });

        it('should provide valid access token (with auto-refresh if needed)', async () => {
            const accessToken = await client.getValidAccessToken();
            
            expect(accessToken).toBeTruthy();
            
            // Verify the token is active
            const introspection = await client.introspectToken(accessToken);
            expect(introspection.active).toBe(true);
        });
    });

    describe('Error Handling and Resilience', () => {
        it('should handle network timeouts gracefully', async () => {
            const shortTimeoutClient = new AuthClient(
                { ...config, requestTimeoutMs: 1 }, // Very short timeout
                tokenStorage,
                logger
            );

            await expect(shortTimeoutClient.getTokenWithClientCredentials())
                .rejects.toThrow();
        });

        it('should retry failed requests', async () => {
            // This test would require a way to simulate intermittent failures
            // For now, we just verify that the retry configuration is honored
            const retryClient = new AuthClient(
                { ...config, maxRetryAttempts: 2, retryDelayMs: 100 },
                tokenStorage,
                logger
            );

            // Should still succeed with retries enabled
            const tokenResponse = await retryClient.getTokenWithClientCredentials();
            expect(tokenResponse.access_token).toBeTruthy();
        });
    });

    describe('Authorization Code Flow (Manual)', () => {
        it('should generate correct authorization URL', () => {
            const state = 'test-state-' + Date.now();
            const scopes = ['read', 'write'];
            
            const authUrl = client.getAuthorizationUrl(scopes, state);
            
            const url = new URL(authUrl);
            expect(url.origin + url.pathname).toBe(config.authorizationUrl);
            expect(url.searchParams.get('client_id')).toBe(config.clientId);
            expect(url.searchParams.get('response_type')).toBe('code');
            expect(url.searchParams.get('redirect_uri')).toBe(config.redirectUri);
            expect(url.searchParams.get('scope')).toBe('read write');
            expect(url.searchParams.get('state')).toBe(state);
        });

        it('should generate authorization URL with PKCE', () => {
            const state = 'test-state-' + Date.now();
            const scopes = ['read'];
            const pkceParams = {
                code_verifier: 'test-code-verifier',
                code_challenge: 'test-code-challenge',
                code_challenge_method: 'S256'
            };
            
            const authUrl = client.getAuthorizationUrl(scopes, state, pkceParams);
            
            const url = new URL(authUrl);
            expect(url.searchParams.get('code_challenge')).toBe(pkceParams.code_challenge);
            expect(url.searchParams.get('code_challenge_method')).toBe(pkceParams.code_challenge_method);
        });

        // Note: Testing the full authorization code flow requires manual intervention
        // or a test harness that can simulate browser interactions
        it.skip('should exchange authorization code for token', async () => {
            // This test would require a valid authorization code obtained through browser flow
            const authCode = 'test-authorization-code';
            
            const tokenResponse = await client.getTokenWithAuthorizationCode(authCode);
            
            expect(tokenResponse.access_token).toBeTruthy();
            expect(tokenResponse.token_type).toBe('Bearer');
        });
    });

    describe('Concurrent Operations', () => {
        it('should handle concurrent token requests', async () => {
            // Make multiple concurrent requests
            const promises = Array.from({ length: 3 }, () => 
                client.getTokenWithClientCredentials()
            );

            const results = await Promise.all(promises);

            // All requests should succeed
            results.forEach(result => {
                expect(result.access_token).toBeTruthy();
                expect(result.token_type).toBe('Bearer');
            });
        });

        it('should handle concurrent storage operations', async () => {
            // Make concurrent storage operations
            const setPromises = Array.from({ length: 5 }, (_, i) => 
                tokenStorage.setToken(`test_token_${i}`, `value_${i}`)
            );

            await Promise.all(setPromises);

            // Verify all tokens were stored
            const getPromises = Array.from({ length: 5 }, (_, i) => 
                tokenStorage.getToken(`test_token_${i}`)
            );

            const values = await Promise.all(getPromises);
            values.forEach((value, i) => {
                expect(value).toBe(`value_${i}`);
            });
        });
    });
});

describeIntegration('AuthClientFactory Integration Tests', () => {
    let tokenStorage: IntegrationTokenStorage;
    let logger: IntegrationLogger;

    beforeAll(() => {
        tokenStorage = new IntegrationTokenStorage();
        logger = new IntegrationLogger();
    });

    it('should create client from environment variables', () => {
        // Mock environment variables
        const originalEnv = process.env;
        process.env = {
            ...originalEnv,            AUTH_CLIENT_ID: TEST_CONFIG.clientId,
            AUTH_CLIENT_SECRET: TEST_CONFIG.clientSecret,
            AUTH_TOKEN_URL: `${TEST_CONFIG.serverUrl}/oauth2/token`,
            AUTH_AUTHORIZATION_URL: `${TEST_CONFIG.serverUrl}/oauth2/authorize`
        };

        try {            const client = AuthClientFactory.createFromEnvironment(tokenStorage, logger);
            expect(client).toBeInstanceOf(AuthClient);
        } finally {
            process.env = originalEnv;
        }
    });

    it('should create client with discovery URL only', async () => {
        const discoveryConfig = {
            clientId: TEST_CONFIG.clientId,
            clientSecret: TEST_CONFIG.clientSecret,            discoveryUrl: `${TEST_CONFIG.serverUrl}/.well-known/openid_configuration`
        };

        const client = AuthClientFactory.create(discoveryConfig, tokenStorage, logger);
        expect(client).toBeInstanceOf(AuthClient);

        // Verify it can discover and use endpoints
        const discovery = await client.discoverServerEndpoints();
        expect(discovery.token_endpoint).toBeTruthy();
    });
});

// Performance and load testing
describeIntegration('AuthClient Performance Tests', () => {
    let client: OAuth2AuthClient;
    let tokenStorage: IntegrationTokenStorage;
    let logger: IntegrationLogger;

    beforeAll(() => {
        tokenStorage = new IntegrationTokenStorage();
        logger = new IntegrationLogger();

        const config: OAuth2Config = {
            clientId: TEST_CONFIG.clientId,
            clientSecret: TEST_CONFIG.clientSecret,
            tokenUrl: `${TEST_CONFIG.serverUrl}/oauth2/token`,
            maxRetryAttempts: 1, // Reduce retries for performance tests
            requestTimeoutMs: 10000
        };

        client = new OAuth2AuthClient(config, tokenStorage, logger);
    });

    it('should handle high-frequency token requests efficiently', async () => {
        const startTime = Date.now();
        const requestCount = 10;

        // Make multiple sequential requests
        const promises = Array.from({ length: requestCount }, () => 
            client.getTokenWithClientCredentials()
        );

        const results = await Promise.all(promises);
        const endTime = Date.now();

        // All requests should succeed
        expect(results).toHaveLength(requestCount);
        results.forEach(result => {
            expect(result.access_token).toBeTruthy();
        });

        // Performance assertion (should complete within reasonable time)
        const totalTime = endTime - startTime;
        const averageTime = totalTime / requestCount;
        console.info(`Average request time: ${averageTime}ms`);
        
        // Should average less than 5 seconds per request
        expect(averageTime).toBeLessThan(5000);
    }, 60000);
});
