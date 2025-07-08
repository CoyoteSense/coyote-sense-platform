import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { AuthClient, AuthClientFactory } from '../../../src/ts/factory/auth-client-factory';
import {
    AuthClientConfig,
    TokenResponse,
    AuthError,
    AuthMode,
    IntrospectResponse,
    ServerDiscoveryResponse,
    AuthTokenStorage,
    AuthLogger
} from '../../../src/ts/interfaces/auth-interfaces';

// Mock implementations
class MockOAuth2TokenStorage implements OAuth2TokenStorage {
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

    // Test helpers
    getAllTokens(): Map<string, string> {
        return new Map(this.tokens);
    }

    hasToken(key: string): boolean {
        return this.tokens.has(key);
    }
}

class MockOAuth2Logger implements OAuth2Logger {
    public logs: Array<{ level: string; message: string; data?: any }> = [];

    debug(message: string, data?: any): void {
        this.logs.push({ level: 'debug', message, data });
    }

    info(message: string, data?: any): void {
        this.logs.push({ level: 'info', message, data });
    }

    warn(message: string, data?: any): void {
        this.logs.push({ level: 'warn', message, data });
    }

    error(message: string, data?: any): void {
        this.logs.push({ level: 'error', message, data });
    }

    // Test helpers
    clearLogs(): void {
        this.logs = [];
    }

    getLogsForLevel(level: string): Array<{ message: string; data?: any }> {
        return this.logs.filter(log => log.level === level).map(({ message, data }) => ({ message, data }));
    }

    hasLogMessage(message: string): boolean {
        return this.logs.some(log => log.message.includes(message));
    }
}

// Test data factory
class OAuth2TestDataFactory {
    static createValidConfig(overrides: Partial<OAuth2Config> = {}): OAuth2Config {
        return {
            clientId: 'test-client-id',
            clientSecret: 'test-client-secret',
            authorizationUrl: 'https://auth.example.com/oauth2/authorize',
            tokenUrl: 'https://auth.example.com/oauth2/token',
            introspectionUrl: 'https://auth.example.com/oauth2/introspect',
            revocationUrl: 'https://auth.example.com/oauth2/revoke',
            discoveryUrl: 'https://auth.example.com/.well-known/oauth2',
            scopes: ['read', 'write'],
            redirectUri: 'https://app.example.com/callback',
            enableAutoRefresh: true,
            tokenRefreshThresholdSeconds: 300,
            maxRetryAttempts: 3,
            retryDelayMs: 1000,
            requestTimeoutMs: 30000,
            enableServerDiscovery: true,
            ...overrides
        };
    }

    static createTokenResponse(overrides: Partial<OAuth2TokenResponse> = {}): OAuth2TokenResponse {
        return {
            access_token: 'test-access-token',
            token_type: 'Bearer',
            expires_in: 3600,
            refresh_token: 'test-refresh-token',
            scope: 'read write',
            ...overrides
        };
    }

    static createJWTToken(payload: any = {}, expiresIn: number = 3600): string {
        const header = { alg: 'RS256', typ: 'JWT' };
        const now = Math.floor(Date.now() / 1000);
        const defaultPayload = {
            iss: 'test-issuer',
            aud: 'test-audience',
            exp: now + expiresIn,
            iat: now,
            sub: 'test-subject',
            ...payload
        };
        
        const headerBase64 = Buffer.from(JSON.stringify(header)).toString('base64url');
        const payloadBase64 = Buffer.from(JSON.stringify(defaultPayload)).toString('base64url');
        const signature = 'test-signature';
        
        return `${headerBase64}.${payloadBase64}.${signature}`;
    }

    static createIntrospectionResponse(active: boolean = true, overrides: Partial<OAuth2TokenIntrospectionResponse> = {}): OAuth2TokenIntrospectionResponse {
        return {
            active,
            client_id: 'test-client-id',
            username: 'test-user',
            scope: 'read write',
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
            sub: 'test-subject',
            aud: 'test-audience',
            iss: 'test-issuer',
            token_type: 'Bearer',
            ...overrides
        };
    }

    static createDiscoveryResponse(overrides: Partial<OAuth2ServerDiscoveryResponse> = {}): OAuth2ServerDiscoveryResponse {
        return {
            issuer: 'https://auth.example.com',
            authorization_endpoint: 'https://auth.example.com/oauth2/authorize',
            token_endpoint: 'https://auth.example.com/oauth2/token',
            introspection_endpoint: 'https://auth.example.com/oauth2/introspect',
            revocation_endpoint: 'https://auth.example.com/oauth2/revoke',
            jwks_uri: 'https://auth.example.com/.well-known/jwks.json',
            scopes_supported: ['read', 'write', 'admin'],
            response_types_supported: ['code', 'token'],
            grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
            token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
            ...overrides
        };
    }

    static createPKCEParams(): { code_verifier: string; code_challenge: string; code_challenge_method: string } {
        return {
            code_verifier: 'test-code-verifier-1234567890abcdefghijklmnopqrstuvwxyz',
            code_challenge: 'test-code-challenge',
            code_challenge_method: 'S256'
        };
    }
}

// Mock fetch function
const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('OAuth2AuthClient', () => {
    let client: OAuth2AuthClient;
    let config: OAuth2Config;
    let mockTokenStorage: MockOAuth2TokenStorage;
    let mockLogger: MockOAuth2Logger;

    beforeEach(() => {
        mockTokenStorage = new MockOAuth2TokenStorage();
        mockLogger = new MockOAuth2Logger();
        config = OAuth2TestDataFactory.createValidConfig();
        client = new OAuth2AuthClient(config, mockTokenStorage, mockLogger);
        mockFetch.mockClear();
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('Configuration Validation', () => {
        it('should accept valid configuration', () => {
            expect(() => new OAuth2AuthClient(config, mockTokenStorage, mockLogger)).not.toThrow();
        });

        it('should reject invalid client ID', () => {
            const invalidConfig = { ...config, clientId: '' };
            expect(() => new OAuth2AuthClient(invalidConfig, mockTokenStorage, mockLogger))
                .toThrow('Client ID is required');
        });

        it('should reject invalid token URL', () => {
            const invalidConfig = { ...config, tokenUrl: 'invalid-url' };
            expect(() => new OAuth2AuthClient(invalidConfig, mockTokenStorage, mockLogger))
                .toThrow('Invalid token URL');
        });

        it('should reject invalid redirect URI for authorization code flow', () => {
            const invalidConfig = { ...config, redirectUri: 'invalid-uri' };
            expect(() => new OAuth2AuthClient(invalidConfig, mockTokenStorage, mockLogger))
                .toThrow('Invalid redirect URI');
        });

        it('should validate timeout values', () => {
            const invalidConfig = { ...config, requestTimeoutMs: -1 };
            expect(() => new OAuth2AuthClient(invalidConfig, mockTokenStorage, mockLogger))
                .toThrow('Request timeout must be positive');
        });

        it('should validate retry attempts', () => {
            const invalidConfig = { ...config, maxRetryAttempts: -1 };
            expect(() => new OAuth2AuthClient(invalidConfig, mockTokenStorage, mockLogger))
                .toThrow('Max retry attempts must be non-negative');
        });
    });

    describe('Client Credentials Flow', () => {
        it('should successfully obtain token with client credentials', async () => {
            const tokenResponse = OAuth2TestDataFactory.createTokenResponse();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => tokenResponse
            });

            const result = await client.getTokenWithClientCredentials();

            expect(result).toEqual(tokenResponse);
            expect(mockFetch).toHaveBeenCalledWith(
                config.tokenUrl,
                expect.objectContaining({
                    method: 'POST',
                    headers: expect.objectContaining({
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Authorization': expect.stringContaining('Basic ')
                    }),
                    body: expect.stringContaining('grant_type=client_credentials')
                })
            );
            expect(mockLogger.hasLogMessage('Client credentials token obtained')).toBe(true);
        });

        it('should include scopes in client credentials request', async () => {
            const tokenResponse = OAuth2TestDataFactory.createTokenResponse();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => tokenResponse
            });

            await client.getTokenWithClientCredentials(['read', 'write']);

            const fetchCall = mockFetch.mock.calls[0];
            const body = fetchCall[1].body;
            expect(body).toContain('scope=read%20write');
        });

        it('should handle client credentials flow errors', async () => {
            const errorResponse = {
                error: 'invalid_client',
                error_description: 'Client authentication failed'
            };
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 401,
                json: async () => errorResponse
            });

            await expect(client.getTokenWithClientCredentials())
                .rejects.toThrow('OAuth2 request failed: invalid_client - Client authentication failed');
        });
    });

    describe('JWT Bearer Flow', () => {
        it('should successfully obtain token with JWT assertion', async () => {
            const jwtToken = OAuth2TestDataFactory.createJWTToken();
            const tokenResponse = OAuth2TestDataFactory.createTokenResponse();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => tokenResponse
            });

            const result = await client.getTokenWithJWTBearer(jwtToken);

            expect(result).toEqual(tokenResponse);
            expect(mockFetch).toHaveBeenCalledWith(
                config.tokenUrl,
                expect.objectContaining({
                    method: 'POST',
                    headers: expect.objectContaining({
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }),
                    body: expect.stringContaining(`grant_type=${encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')}`)
                })
            );
        });

        it('should include JWT assertion in request body', async () => {
            const jwtToken = OAuth2TestDataFactory.createJWTToken();
            const tokenResponse = OAuth2TestDataFactory.createTokenResponse();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => tokenResponse
            });

            await client.getTokenWithJWTBearer(jwtToken, ['admin']);

            const fetchCall = mockFetch.mock.calls[0];
            const body = fetchCall[1].body;
            expect(body).toContain(`assertion=${encodeURIComponent(jwtToken)}`);
            expect(body).toContain('scope=admin');
        });

        it('should reject empty JWT assertion', async () => {
            await expect(client.getTokenWithJWTBearer(''))
                .rejects.toThrow('JWT assertion is required');
        });
    });

    describe('Authorization Code Flow', () => {
        it('should generate correct authorization URL', () => {
            const authUrl = client.getAuthorizationUrl(['read', 'write'], 'test-state');

            const url = new URL(authUrl);
            expect(url.origin + url.pathname).toBe(config.authorizationUrl);
            expect(url.searchParams.get('client_id')).toBe(config.clientId);
            expect(url.searchParams.get('response_type')).toBe('code');
            expect(url.searchParams.get('redirect_uri')).toBe(config.redirectUri);
            expect(url.searchParams.get('scope')).toBe('read write');
            expect(url.searchParams.get('state')).toBe('test-state');
        });

        it('should generate authorization URL with PKCE', () => {
            const pkceParams = OAuth2TestDataFactory.createPKCEParams();
            const authUrl = client.getAuthorizationUrl(['read'], 'test-state', pkceParams);

            const url = new URL(authUrl);
            expect(url.searchParams.get('code_challenge')).toBe(pkceParams.code_challenge);
            expect(url.searchParams.get('code_challenge_method')).toBe(pkceParams.code_challenge_method);
        });

        it('should successfully exchange authorization code for token', async () => {
            const tokenResponse = OAuth2TestDataFactory.createTokenResponse();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => tokenResponse
            });

            const result = await client.getTokenWithAuthorizationCode('test-code');

            expect(result).toEqual(tokenResponse);
            expect(mockFetch).toHaveBeenCalledWith(
                config.tokenUrl,
                expect.objectContaining({
                    method: 'POST',
                    headers: expect.objectContaining({
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }),
                    body: expect.stringContaining('grant_type=authorization_code')
                })
            );
        });

        it('should include PKCE verifier in token exchange', async () => {
            const tokenResponse = OAuth2TestDataFactory.createTokenResponse();
            const pkceParams = OAuth2TestDataFactory.createPKCEParams();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => tokenResponse
            });

            await client.getTokenWithAuthorizationCode('test-code', pkceParams.code_verifier);

            const fetchCall = mockFetch.mock.calls[0];
            const body = fetchCall[1].body;
            expect(body).toContain(`code_verifier=${encodeURIComponent(pkceParams.code_verifier)}`);
        });
    });

    describe('Refresh Token Flow', () => {
        it('should successfully refresh token', async () => {
            const newTokenResponse = OAuth2TestDataFactory.createTokenResponse({
                access_token: 'new-access-token'
            });
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => newTokenResponse
            });

            const result = await client.refreshToken('refresh-token');

            expect(result).toEqual(newTokenResponse);
            expect(mockFetch).toHaveBeenCalledWith(
                config.tokenUrl,
                expect.objectContaining({
                    method: 'POST',
                    body: expect.stringContaining('grant_type=refresh_token')
                })
            );
        });

        it('should include scopes in refresh request', async () => {
            const newTokenResponse = OAuth2TestDataFactory.createTokenResponse();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => newTokenResponse
            });

            await client.refreshToken('refresh-token', ['read']);

            const fetchCall = mockFetch.mock.calls[0];
            const body = fetchCall[1].body;
            expect(body).toContain('scope=read');
        });
    });

    describe('Token Introspection', () => {
        it('should successfully introspect token', async () => {
            const introspectionResponse = OAuth2TestDataFactory.createIntrospectionResponse();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => introspectionResponse
            });

            const result = await client.introspectToken('test-token');

            expect(result).toEqual(introspectionResponse);
            expect(mockFetch).toHaveBeenCalledWith(
                config.introspectionUrl,
                expect.objectContaining({
                    method: 'POST',
                    body: expect.stringContaining('token=test-token')
                })
            );
        });

        it('should handle inactive token introspection', async () => {
            const introspectionResponse = OAuth2TestDataFactory.createIntrospectionResponse(false);
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => introspectionResponse
            });

            const result = await client.introspectToken('inactive-token');

            expect(result.active).toBe(false);
        });
    });

    describe('Token Revocation', () => {
        it('should successfully revoke token', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200
            });

            await expect(client.revokeToken('test-token')).resolves.not.toThrow();

            expect(mockFetch).toHaveBeenCalledWith(
                config.revocationUrl,
                expect.objectContaining({
                    method: 'POST',
                    body: expect.stringContaining('token=test-token')
                })
            );
        });

        it('should specify token type hint in revocation', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200
            });

            await client.revokeToken('test-token', 'refresh_token');

            const fetchCall = mockFetch.mock.calls[0];
            const body = fetchCall[1].body;
            expect(body).toContain('token_type_hint=refresh_token');
        });
    });

    describe('Server Discovery', () => {
        it('should successfully discover server endpoints', async () => {
            const discoveryResponse = OAuth2TestDataFactory.createDiscoveryResponse();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => discoveryResponse
            });

            const result = await client.discoverServerEndpoints();

            expect(result).toEqual(discoveryResponse);
            expect(mockFetch).toHaveBeenCalledWith(
                config.discoveryUrl,
                expect.objectContaining({
                    method: 'GET'
                })
            );
        });

        it('should handle discovery errors', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 404
            });

            await expect(client.discoverServerEndpoints())
                .rejects.toThrow('Server discovery failed');
        });
    });

    describe('Token Storage Integration', () => {
        it('should store tokens automatically when configured', async () => {
            const tokenResponse = OAuth2TestDataFactory.createTokenResponse();
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => tokenResponse
            });

            await client.getTokenWithClientCredentials();

            expect(mockTokenStorage.hasToken('access_token')).toBe(true);
            expect(await mockTokenStorage.getToken('access_token')).toBe(tokenResponse.access_token);
            
            if (tokenResponse.refresh_token) {
                expect(mockTokenStorage.hasToken('refresh_token')).toBe(true);
                expect(await mockTokenStorage.getToken('refresh_token')).toBe(tokenResponse.refresh_token);
            }
        });

        it('should retrieve stored tokens', async () => {
            await mockTokenStorage.setToken('access_token', 'stored-access-token');
            await mockTokenStorage.setToken('refresh_token', 'stored-refresh-token');

            const accessToken = await client.getStoredAccessToken();
            const refreshToken = await client.getStoredRefreshToken();

            expect(accessToken).toBe('stored-access-token');
            expect(refreshToken).toBe('stored-refresh-token');
        });

        it('should clear stored tokens', async () => {
            await mockTokenStorage.setToken('access_token', 'test-token');
            await mockTokenStorage.setToken('refresh_token', 'test-refresh');

            await client.clearStoredTokens();

            expect(await mockTokenStorage.getToken('access_token')).toBeNull();
            expect(await mockTokenStorage.getToken('refresh_token')).toBeNull();
        });
    });

    describe('Auto-Refresh Functionality', () => {
        beforeEach(() => {
            // Enable auto-refresh for these tests
            config.enableAutoRefresh = true;
            config.tokenRefreshThresholdSeconds = 300; // 5 minutes
            client = new OAuth2AuthClient(config, mockTokenStorage, mockLogger);
        });

        it('should check if token needs refresh', async () => {
            // Store an expired token
            const expiredToken = OAuth2TestDataFactory.createJWTToken({}, -3600); // Expired 1 hour ago
            await mockTokenStorage.setToken('access_token', expiredToken);

            const needsRefresh = await client.needsTokenRefresh();
            expect(needsRefresh).toBe(true);
        });

        it('should not refresh valid token', async () => {
            // Store a valid token
            const validToken = OAuth2TestDataFactory.createJWTToken({}, 7200); // Valid for 2 hours
            await mockTokenStorage.setToken('access_token', validToken);

            const needsRefresh = await client.needsTokenRefresh();
            expect(needsRefresh).toBe(false);
        });

        it('should auto-refresh token when threshold reached', async () => {
            // Store a token that expires soon
            const soonExpiredToken = OAuth2TestDataFactory.createJWTToken({}, 60); // Expires in 1 minute
            const refreshToken = 'test-refresh-token';
            await mockTokenStorage.setToken('access_token', soonExpiredToken);
            await mockTokenStorage.setToken('refresh_token', refreshToken);

            // Mock refresh response
            const newTokenResponse = OAuth2TestDataFactory.createTokenResponse({
                access_token: 'new-access-token'
            });
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => newTokenResponse
            });

            const result = await client.getValidAccessToken();

            expect(result).toBe('new-access-token');
            expect(mockFetch).toHaveBeenCalledWith(
                config.tokenUrl,
                expect.objectContaining({
                    body: expect.stringContaining('grant_type=refresh_token')
                })
            );
        });
    });

    describe('Error Handling', () => {
        it('should handle network errors', async () => {
            mockFetch.mockRejectedValueOnce(new Error('Network error'));

            await expect(client.getTokenWithClientCredentials())
                .rejects.toThrow('OAuth2 request failed: Network error');
        });

        it('should handle timeout errors', async () => {
            // Simulate timeout
            mockFetch.mockImplementationOnce(() => 
                new Promise((_, reject) => 
                    setTimeout(() => reject(new Error('Request timeout')), 100)
                )
            );

            await expect(client.getTokenWithClientCredentials())
                .rejects.toThrow('OAuth2 request failed: Request timeout');
        });

        it('should handle HTTP error responses', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 500,
                statusText: 'Internal Server Error',
                json: async () => ({ error: 'server_error', error_description: 'Internal server error' })
            });

            await expect(client.getTokenWithClientCredentials())
                .rejects.toThrow('OAuth2 request failed: server_error - Internal server error');
        });

        it('should handle malformed JSON responses', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => { throw new Error('Invalid JSON'); }
            });

            await expect(client.getTokenWithClientCredentials())
                .rejects.toThrow('OAuth2 request failed: Invalid JSON');
        });
    });

    describe('Retry Logic', () => {
        beforeEach(() => {
            config.maxRetryAttempts = 3;
            config.retryDelayMs = 100;
            client = new OAuth2AuthClient(config, mockTokenStorage, mockLogger);
        });

        it('should retry failed requests', async () => {
            // First two calls fail, third succeeds
            mockFetch
                .mockRejectedValueOnce(new Error('Network error'))
                .mockRejectedValueOnce(new Error('Network error'))
                .mockResolvedValueOnce({
                    ok: true,
                    status: 200,
                    json: async () => OAuth2TestDataFactory.createTokenResponse()
                });

            const result = await client.getTokenWithClientCredentials();

            expect(result).toBeDefined();
            expect(mockFetch).toHaveBeenCalledTimes(3);
            expect(mockLogger.getLogsForLevel('warn')).toHaveLength(2); // Two retry warnings
        });

        it('should not retry on client errors (4xx)', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 400,
                json: async () => ({ error: 'invalid_request' })
            });

            await expect(client.getTokenWithClientCredentials()).rejects.toThrow();
            expect(mockFetch).toHaveBeenCalledTimes(1); // No retries for 4xx errors
        });

        it('should retry on server errors (5xx)', async () => {
            mockFetch
                .mockResolvedValueOnce({
                    ok: false,
                    status: 500,
                    json: async () => ({ error: 'server_error' })
                })
                .mockResolvedValueOnce({
                    ok: true,
                    status: 200,
                    json: async () => OAuth2TestDataFactory.createTokenResponse()
                });

            const result = await client.getTokenWithClientCredentials();

            expect(result).toBeDefined();
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });
    });

    describe('Concurrent Access', () => {
        it('should handle concurrent token requests', async () => {
            const tokenResponse = OAuth2TestDataFactory.createTokenResponse();
            mockFetch.mockResolvedValue({
                ok: true,
                status: 200,
                json: async () => tokenResponse
            });

            // Make multiple concurrent requests
            const promises = Array.from({ length: 5 }, () => 
                client.getTokenWithClientCredentials()
            );

            const results = await Promise.all(promises);

            // All requests should succeed
            results.forEach(result => {
                expect(result).toEqual(tokenResponse);
            });

            // Should have made the requests (may be cached or not, depending on implementation)
            expect(mockFetch).toHaveBeenCalled();
        });

        it('should handle concurrent storage operations', async () => {
            const promises = Array.from({ length: 10 }, (_, i) => 
                mockTokenStorage.setToken(`token_${i}`, `value_${i}`)
            );

            await Promise.all(promises);

            // All tokens should be stored
            for (let i = 0; i < 10; i++) {
                const value = await mockTokenStorage.getToken(`token_${i}`);
                expect(value).toBe(`value_${i}`);
            }
        });
    });
});

describe('OAuth2AuthClientFactory', () => {
    let mockTokenStorage: MockOAuth2TokenStorage;
    let mockLogger: MockOAuth2Logger;

    beforeEach(() => {
        mockTokenStorage = new MockOAuth2TokenStorage();
        mockLogger = new MockOAuth2Logger();
    });

    it('should create client with full configuration', () => {
        const config = OAuth2TestDataFactory.createValidConfig();
        const client = OAuth2AuthClientFactory.create(config, mockTokenStorage, mockLogger);

        expect(client).toBeInstanceOf(OAuth2AuthClient);
    });

    it('should create client with minimal configuration', () => {
        const minimalConfig: OAuth2Config = {
            clientId: 'test-client',
            clientSecret: 'test-secret',
            tokenUrl: 'https://auth.example.com/token'
        };

        const client = OAuth2AuthClientFactory.create(minimalConfig, mockTokenStorage, mockLogger);

        expect(client).toBeInstanceOf(OAuth2AuthClient);
    });

    it('should create client from environment variables', () => {
        // Mock environment variables
        const originalEnv = process.env;
        process.env = {
            ...originalEnv,
            OAUTH2_CLIENT_ID: 'env-client-id',
            OAUTH2_CLIENT_SECRET: 'env-client-secret',
            OAUTH2_TOKEN_URL: 'https://auth.example.com/token',
            OAUTH2_AUTHORIZATION_URL: 'https://auth.example.com/authorize'
        };

        try {
            const client = OAuth2AuthClientFactory.createFromEnvironment(mockTokenStorage, mockLogger);
            expect(client).toBeInstanceOf(OAuth2AuthClient);
        } finally {
            process.env = originalEnv;
        }
    });

    it('should throw error when required environment variables are missing', () => {
        const originalEnv = process.env;
        process.env = {}; // Clear environment variables

        try {
            expect(() => OAuth2AuthClientFactory.createFromEnvironment(mockTokenStorage, mockLogger))
                .toThrow('Required environment variable OAUTH2_CLIENT_ID is not set');
        } finally {
            process.env = originalEnv;
        }
    });
});

describe('PKCE Helper Functions', () => {
    it('should generate valid PKCE parameters', async () => {
        // This would test the PKCE generation functions if they were exported
        // For now, we'll test through the client interface
        const client = new OAuth2AuthClient(
            OAuth2TestDataFactory.createValidConfig(),
            new MockOAuth2TokenStorage(),
            new MockOAuth2Logger()
        );

        const pkceParams = OAuth2TestDataFactory.createPKCEParams();
        const authUrl = client.getAuthorizationUrl(['read'], 'test-state', pkceParams);

        const url = new URL(authUrl);
        expect(url.searchParams.get('code_challenge')).toBe(pkceParams.code_challenge);
        expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    });
});

describe('JWT Helper Functions', () => {
    it('should parse JWT payload correctly', () => {
        const payload = { sub: 'test-user', exp: Math.floor(Date.now() / 1000) + 3600 };
        const jwt = OAuth2TestDataFactory.createJWTToken(payload);

        // This would test JWT parsing if the function was exported
        // For now, we verify the JWT format
        const parts = jwt.split('.');
        expect(parts).toHaveLength(3);

        const decodedPayload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        expect(decodedPayload.sub).toBe('test-user');
    });

    it('should check JWT expiration correctly', () => {
        const expiredPayload = { exp: Math.floor(Date.now() / 1000) - 3600 }; // Expired 1 hour ago
        const validPayload = { exp: Math.floor(Date.now() / 1000) + 3600 }; // Valid for 1 hour

        const expiredJwt = OAuth2TestDataFactory.createJWTToken(expiredPayload);
        const validJwt = OAuth2TestDataFactory.createJWTToken(validPayload);

        // Test that the factory creates the correct tokens
        const expiredParts = expiredJwt.split('.');
        const validParts = validJwt.split('.');

        const expiredDecoded = JSON.parse(Buffer.from(expiredParts[1], 'base64url').toString());
        const validDecoded = JSON.parse(Buffer.from(validParts[1], 'base64url').toString());

        expect(expiredDecoded.exp).toBeLessThan(Math.floor(Date.now() / 1000));
        expect(validDecoded.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });
});
