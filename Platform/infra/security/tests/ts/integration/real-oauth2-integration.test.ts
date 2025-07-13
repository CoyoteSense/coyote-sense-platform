/**
 * Real OAuth2 Server Integration Tests
 * 
 * Tests the TypeScript OAuth2 client against a real OAuth2 server running in Docker.
 * This test suite verifies that the client can successfully authenticate and interact
 * with the OAuth2 server at http://localhost:8081.
 * 
 * Prerequisites:
 * - OAuth2 server must be running (docker-compose.oauth2.yml)
 * - Server should be accessible at http://localhost:8081
 * - Test client credentials: test-client-id / test-client-secret
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';

// Import real fetch for Node.js
import fetch from 'cross-fetch';

// Disable fetch mocking for this test file
const fetchMock = require('jest-fetch-mock');
fetchMock.disableMocks();

// Simple fetch implementation for OAuth2 requests
interface OAuth2TokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    scope?: string;
}

interface OAuth2IntrospectionResponse {
    active: boolean;
    client_id?: string;
    username?: string;
    scope?: string;
    exp?: number;
    token_type?: string;
}

/**
 * Simple OAuth2 client for integration testing
 */
class SimpleOAuth2Client {
    private baseUrl: string;
    private clientId: string;
    private clientSecret: string;

    constructor(baseUrl: string, clientId: string, clientSecret: string) {
        this.baseUrl = baseUrl.replace(/\/$/, ''); // Remove trailing slash
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    /**
     * Get access token using client credentials flow
     */
    async getClientCredentialsToken(scopes?: string[]): Promise<OAuth2TokenResponse> {
        const body = new URLSearchParams({
            grant_type: 'client_credentials',
            client_id: this.clientId,
            client_secret: this.clientSecret
        });

        if (scopes && scopes.length > 0) {
            body.append('scope', scopes.join(' '));
        }

        const response = await fetch(`${this.baseUrl}/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            body: body.toString()
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`OAuth2 token request failed: ${response.status} ${response.statusText} - ${errorText}`);
        }

        const responseText = await response.text();
        console.log('🐛 Raw response:', responseText);
        
        try {
            return JSON.parse(responseText) as OAuth2TokenResponse;
        } catch (parseError) {
            throw new Error(`Failed to parse token response: ${parseError} - Raw response: ${responseText}`);
        }
    }

    /**
     * Introspect a token to check its validity
     */
    async introspectToken(token: string): Promise<OAuth2IntrospectionResponse> {
        const body = new URLSearchParams({
            token: token,
            client_id: this.clientId,
            client_secret: this.clientSecret
        });

        const response = await fetch(`${this.baseUrl}/introspect`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            body: body.toString()
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`OAuth2 introspection request failed: ${response.status} ${response.statusText} - ${errorText}`);
        }

        return await response.json() as OAuth2IntrospectionResponse;
    }

    /**
     * Check server health
     */
    async checkServerHealth(): Promise<boolean> {
        try {
            const response = await fetch(`${this.baseUrl}/health`, {
                method: 'GET',
                headers: { 'Accept': 'application/json' }
            });
            return response.ok;
        } catch (error) {
            return false;
        }
    }

    /**
     * Get server discovery information
     */
    async getServerInfo(): Promise<any> {
        const response = await fetch(`${this.baseUrl}/.well-known/oauth2`, {
            method: 'GET',
            headers: { 'Accept': 'application/json' }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Server info request failed: ${response.status} ${response.statusText}`);
        }

        const responseText = await response.text();
        console.log('🐛 Raw discovery response:', responseText);
        
        try {
            return JSON.parse(responseText);
        } catch (parseError) {
            throw new Error(`Failed to parse discovery response: ${parseError} - Raw response: ${responseText}`);
        }
    }
}

// Test configuration
const TEST_CONFIG = {
    serverUrl: 'http://localhost:8081',
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    scopes: ['read', 'write']
};

describe('Real OAuth2 Server Integration Tests (TypeScript)', () => {
    let client: SimpleOAuth2Client;
    let serverAvailable: boolean = false;

    beforeAll(async () => {
        // Initialize OAuth2 client
        client = new SimpleOAuth2Client(
            TEST_CONFIG.serverUrl,
            TEST_CONFIG.clientId,
            TEST_CONFIG.clientSecret
        );

        // Check if server is available
        console.log(`Checking OAuth2 server availability at ${TEST_CONFIG.serverUrl}...`);
        serverAvailable = await client.checkServerHealth();
        
        if (!serverAvailable) {
            console.warn(`⚠️  OAuth2 server not available at ${TEST_CONFIG.serverUrl}`);
            console.warn('   Make sure to start the server with: docker-compose -f docker-compose.oauth2.yml up -d');
        } else {
            console.log('✅ OAuth2 server is available and healthy');
        }
    }, 30000);

    beforeEach(() => {
        if (!serverAvailable) {
            console.log('⏭️  Skipping test - OAuth2 server not available');
        }
    });

    describe('Server Connectivity', () => {
        it('should connect to OAuth2 server successfully', async () => {
            if (!serverAvailable) {
                pending('OAuth2 server not available');
                return;
            }

            const isHealthy = await client.checkServerHealth();
            expect(isHealthy).toBe(true);
        });

        it('should get server discovery information', async () => {
            if (!serverAvailable) {
                pending('OAuth2 server not available');
                return;
            }

            const serverInfo = await client.getServerInfo();
            expect(serverInfo).toBeDefined();
            expect(typeof serverInfo).toBe('object');
            expect(serverInfo.issuer).toBeTruthy();
            expect(serverInfo.token_endpoint).toBeTruthy();
            
            console.log('📋 Server discovery info:', JSON.stringify(serverInfo, null, 2));
        });
    });

    describe('Client Credentials Flow', () => {
        it('should obtain access token with client credentials', async () => {
            if (!serverAvailable) {
                pending('OAuth2 server not available');
                return;
            }

            const tokenResponse = await client.getClientCredentialsToken();

            expect(tokenResponse).toBeDefined();
            expect(tokenResponse.access_token).toBeTruthy();
            expect(typeof tokenResponse.access_token).toBe('string');
            expect(tokenResponse.token_type).toBe('Bearer');
            expect(tokenResponse.expires_in).toBeGreaterThan(0);
            expect(typeof tokenResponse.expires_in).toBe('number');

            console.log('🔑 Token obtained:', {
                token_type: tokenResponse.token_type,
                expires_in: tokenResponse.expires_in,
                has_token: !!tokenResponse.access_token,
                scope: tokenResponse.scope
            });
        });

        it('should obtain access token with specific scopes', async () => {
            if (!serverAvailable) {
                pending('OAuth2 server not available');
                return;
            }

            const tokenResponse = await client.getClientCredentialsToken(['read']);

            expect(tokenResponse).toBeDefined();
            expect(tokenResponse.access_token).toBeTruthy();
            expect(tokenResponse.token_type).toBe('Bearer');
            
            // Check if scope is returned (not all servers return scope in response)
            if (tokenResponse.scope) {
                expect(tokenResponse.scope).toContain('read');
            }

            console.log('🎯 Scoped token obtained:', {
                requested_scope: 'read',
                returned_scope: tokenResponse.scope
            });
        });

        it('should handle invalid client credentials gracefully', async () => {
            if (!serverAvailable) {
                pending('OAuth2 server not available');
                return;
            }

            const invalidClient = new SimpleOAuth2Client(
                TEST_CONFIG.serverUrl,
                'invalid-client-id',
                'invalid-secret'
            );

            await expect(invalidClient.getClientCredentialsToken())
                .rejects.toThrow();

            console.log('❌ Invalid credentials properly rejected');
        });
    });

    describe('Token Introspection', () => {
        let validAccessToken: string;

        beforeEach(async () => {
            if (!serverAvailable) {
                return;
            }

            // Get a valid token for introspection tests
            const tokenResponse = await client.getClientCredentialsToken();
            validAccessToken = tokenResponse.access_token;
        });

        it('should successfully introspect valid token', async () => {
            if (!serverAvailable) {
                pending('OAuth2 server not available');
                return;
            }

            const introspection = await client.introspectToken(validAccessToken);

            expect(introspection).toBeDefined();
            expect(introspection.active).toBe(true);
            
            // Check optional fields if present
            if (introspection.client_id) {
                expect(introspection.client_id).toBe(TEST_CONFIG.clientId);
            }
            if (introspection.exp) {
                expect(introspection.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
            }

            console.log('🔍 Token introspection result:', {
                active: introspection.active,
                client_id: introspection.client_id,
                expires_at: introspection.exp ? new Date(introspection.exp * 1000).toISOString() : 'not provided',
                scope: introspection.scope
            });
        });

        it('should return inactive for invalid token', async () => {
            if (!serverAvailable) {
                pending('OAuth2 server not available');
                return;
            }

            const introspection = await client.introspectToken('invalid-token-12345');

            expect(introspection).toBeDefined();
            expect(introspection.active).toBe(false);

            console.log('🚫 Invalid token properly marked as inactive');
        });
    });

    describe('Error Handling', () => {
        it('should handle network errors gracefully', async () => {
            // Test with a non-existent server
            const offlineClient = new SimpleOAuth2Client(
                'http://localhost:9999',
                TEST_CONFIG.clientId,
                TEST_CONFIG.clientSecret
            );

            await expect(offlineClient.getClientCredentialsToken())
                .rejects.toThrow();

            console.log('🌐 Network errors properly handled');
        });

        it('should handle malformed requests', async () => {
            if (!serverAvailable) {
                pending('OAuth2 server not available');
                return;
            }

            // Test with empty client credentials
            const emptyClient = new SimpleOAuth2Client(
                TEST_CONFIG.serverUrl,
                '',
                ''
            );

            await expect(emptyClient.getClientCredentialsToken())
                .rejects.toThrow();

            console.log('📝 Malformed requests properly rejected');
        });
    });

    describe('Performance', () => {
        it('should complete token request within reasonable time', async () => {
            if (!serverAvailable) {
                pending('OAuth2 server not available');
                return;
            }

            const startTime = Date.now();
            const tokenResponse = await client.getClientCredentialsToken();
            const endTime = Date.now();
            const duration = endTime - startTime;

            expect(tokenResponse).toBeDefined();
            expect(duration).toBeLessThan(5000); // Should complete within 5 seconds

            console.log(`⚡ Token request completed in ${duration}ms`);
        });

        it('should handle multiple concurrent requests', async () => {
            if (!serverAvailable) {
                pending('OAuth2 server not available');
                return;
            }

            const concurrentRequests = 5;
            const startTime = Date.now();

            const promises = Array.from({ length: concurrentRequests }, () =>
                client.getClientCredentialsToken()
            );

            const results = await Promise.all(promises);
            const endTime = Date.now();
            const duration = endTime - startTime;

            expect(results).toHaveLength(concurrentRequests);
            results.forEach(result => {
                expect(result.access_token).toBeTruthy();
                expect(result.token_type).toBe('Bearer');
            });

            console.log(`🔄 ${concurrentRequests} concurrent requests completed in ${duration}ms`);
        });
    });
});
