/**
 * Authentication Client Factory for JavaScript
 * 
 * This module provides factory methods and builder pattern for creating authentication clients
 * in the CoyoteSense platform. Supports multiple authentication standards:
 * - OAuth2 Client Credentials (RFC 6749)
 * - OAuth2 Authorization Code (RFC 6749) 
 * - OAuth2 + PKCE (RFC 7636)
 * - JWT Bearer (RFC 7523)
 * - mTLS Client Credentials (RFC 8705)
 */

const { 
    AuthMode, 
    AuthConfigHelper,
    InMemoryTokenStorage,
    ConsoleAuthLogger 
} = require('../../interfaces/js/auth-interfaces');

/**
 * Builder pattern for creating authentication clients with fluent interface
 */
class AuthClientBuilder {
    constructor() {
        this._config = {};
        this._tokenStorage = null;
        this._logger = null;
    }

    /**
     * Set authentication server URL
     * @param {string} url - The authentication server URL
     * @returns {AuthClientBuilder}
     */
    serverUrl(url) {
        this._config.serverUrl = url;
        return this;
    }

    /**
     * Set client credentials (ID and secret)
     * @param {string} clientId - The client ID
     * @param {string} [clientSecret] - The client secret (optional for public clients)
     * @returns {AuthClientBuilder}
     */
    clientCredentials(clientId, clientSecret) {
        this._config.clientId = clientId;
        if (clientSecret) {
            this._config.clientSecret = clientSecret;
        }
        return this;
    }

    /**
     * Set authentication mode
     * @param {string} mode - The authentication mode
     * @returns {AuthClientBuilder}
     */
    authMode(mode) {
        this._config.authMode = mode;
        return this;
    }

    /**
     * Set default scopes
     * @param {string[]} scopes - Default scopes to request
     * @returns {AuthClientBuilder}
     */
    defaultScopes(scopes) {
        this._config.defaultScopes = scopes;
        return this;
    }

    /**
     * Set mTLS certificates for mTLS authentication
     * @param {string} certPath - Path to client certificate
     * @param {string} keyPath - Path to client private key
     * @param {string} [caCertPath] - Path to CA certificate (optional)
     * @returns {AuthClientBuilder}
     */
    mtlsCertificates(certPath, keyPath, caCertPath) {
        this._config.clientCertPath = certPath;
        this._config.clientKeyPath = keyPath;
        if (caCertPath) {
            this._config.caCertPath = caCertPath;
        }
        return this;
    }

    /**
     * Set JWT settings for JWT Bearer authentication
     * @param {string} signingKeyPath - Path to JWT signing key
     * @param {string} issuer - JWT issuer
     * @param {string} audience - JWT audience
     * @param {string} [algorithm='RS256'] - JWT algorithm
     * @returns {AuthClientBuilder}
     */
    jwtSettings(signingKeyPath, issuer, audience, algorithm = 'RS256') {
        this._config.jwtSigningKeyPath = signingKeyPath;
        this._config.jwtIssuer = issuer;
        this._config.jwtAudience = audience;
        this._config.jwtAlgorithm = algorithm;
        return this;
    }

    /**
     * Set redirect URI for Authorization Code flows
     * @param {string} uri - Redirect URI
     * @returns {AuthClientBuilder}
     */
    redirectUri(uri) {
        this._config.redirectUri = uri;
        return this;
    }

    /**
     * Enable PKCE for Authorization Code flow
     * @param {boolean} [enable=true] - Whether to enable PKCE
     * @returns {AuthClientBuilder}
     */
    enablePkce(enable = true) {
        this._config.usePkce = enable;
        return this;
    }

    /**
     * Set request timeout
     * @param {number} timeoutMs - Timeout in milliseconds
     * @returns {AuthClientBuilder}
     */
    timeout(timeoutMs) {
        this._config.timeoutMs = timeoutMs;
        return this;
    }

    /**
     * Set custom headers
     * @param {Object} headers - Custom headers
     * @returns {AuthClientBuilder}
     */
    customHeaders(headers) {
        this._config.customHeaders = { ...this._config.customHeaders, ...headers };
        return this;
    }

    /**
     * Configure automatic token refresh
     * @param {boolean} [enabled=true] - Enable auto refresh
     * @param {number} [marginSeconds=300] - Refresh margin in seconds
     * @param {number} [checkIntervalMs=60000] - Check interval in milliseconds
     * @returns {AuthClientBuilder}
     */
    autoRefresh(enabled = true, marginSeconds = 300, checkIntervalMs = 60000) {
        this._config.enableAutoRefresh = enabled;
        this._config.refreshMarginSeconds = marginSeconds;
        this._config.refreshCheckIntervalMs = checkIntervalMs;
        return this;
    }

    /**
     * Set token storage implementation
     * @param {Object} storage - Token storage implementation
     * @returns {AuthClientBuilder}
     */
    tokenStorage(storage) {
        this._tokenStorage = storage;
        return this;
    }

    /**
     * Set logger implementation
     * @param {Object} logger - Logger implementation
     * @returns {AuthClientBuilder}
     */
    logger(logger) {
        this._logger = logger;
        return this;
    }

    /**
     * Build the authentication client
     * @param {Object} [httpClient] - HTTP client instance
     * @returns {Object} Authentication client
     */
    build(httpClient) {
        if (!this._config.serverUrl) {
            throw new Error('Server URL is required');
        }
        if (!this._config.clientId) {
            throw new Error('Client ID is required');
        }

        if (!httpClient) {
            throw new Error('HTTP client must be provided in build() method');
        }

        const finalConfig = {
            authMode: this._config.authMode || AuthMode.CLIENT_CREDENTIALS,
            serverUrl: this._config.serverUrl,
            clientId: this._config.clientId,
            clientSecret: this._config.clientSecret,
            defaultScopes: this._config.defaultScopes || [],
            timeoutMs: this._config.timeoutMs || 30000,
            customHeaders: this._config.customHeaders || {},
            enableAutoRefresh: this._config.enableAutoRefresh !== undefined ? this._config.enableAutoRefresh : true,
            refreshMarginSeconds: this._config.refreshMarginSeconds || 300,
            refreshCheckIntervalMs: this._config.refreshCheckIntervalMs || 60000,
            // Include all other configuration properties
            clientCertPath: this._config.clientCertPath,
            clientKeyPath: this._config.clientKeyPath,
            caCertPath: this._config.caCertPath,
            jwtSigningKeyPath: this._config.jwtSigningKeyPath,
            jwtAlgorithm: this._config.jwtAlgorithm,
            jwtIssuer: this._config.jwtIssuer,
            jwtAudience: this._config.jwtAudience,
            redirectUri: this._config.redirectUri,
            usePkce: this._config.usePkce,
            refreshBufferSeconds: this._config.refreshBufferSeconds,
            autoRefresh: this._config.autoRefresh,
            maxRetryAttempts: this._config.maxRetryAttempts,
            retryDelayMs: this._config.retryDelayMs,
            verifySsl: this._config.verifySsl
        };

        // Import the actual client implementation
        const { AuthClient } = require('../../clients/javascript/auth-client');

        return new AuthClient(
            finalConfig,
            httpClient,
            this._tokenStorage,
            this._logger
        );
    }
}

/**
 * Factory class for creating authentication clients with different authentication modes
 */
class AuthClientFactory {
    /**
     * Create a new authentication client builder
     * @returns {AuthClientBuilder}
     */
    static create() {
        return new AuthClientBuilder();
    }

    /**
     * Create authentication client with minimal configuration
     * @param {string} serverUrl - Authentication server URL
     * @param {string} clientId - Client ID
     * @param {string} [clientSecret] - Client secret
     * @param {Object} [httpClient] - HTTP client instance
     * @returns {Object} Authentication client
     */
    static createSimple(serverUrl, clientId, clientSecret, httpClient) {
        return AuthClientFactory.create()
            .serverUrl(serverUrl)
            .clientCredentials(clientId, clientSecret)
            .build(httpClient);
    }

    /**
     * Create authentication client for Client Credentials flow
     * @param {string} serverUrl - Authentication server URL
     * @param {string} clientId - Client ID
     * @param {string} clientSecret - Client secret
     * @param {string[]} [scopes] - Default scopes
     * @param {Object} [httpClient] - HTTP client instance
     * @returns {Object} Authentication client
     */
    static createClientCredentials(serverUrl, clientId, clientSecret, scopes, httpClient) {
        const builder = AuthClientFactory.create()
            .serverUrl(serverUrl)
            .clientCredentials(clientId, clientSecret)
            .authMode(AuthMode.CLIENT_CREDENTIALS);

        if (scopes) {
            builder.defaultScopes(scopes);
        }

        return builder.build(httpClient);
    }

    /**
     * Create authentication client for Client Credentials with mTLS flow
     * @param {string} serverUrl - Authentication server URL
     * @param {string} clientId - Client ID
     * @param {string} clientCertPath - Path to client certificate
     * @param {string} clientKeyPath - Path to client private key
     * @param {string} [caCertPath] - Path to CA certificate
     * @param {string[]} [scopes] - Default scopes
     * @param {Object} [httpClient] - HTTP client instance
     * @returns {Object} Authentication client
     */
    static createClientCredentialsMtls(serverUrl, clientId, clientCertPath, clientKeyPath, caCertPath, scopes, httpClient) {
        const builder = AuthClientFactory.create()
            .serverUrl(serverUrl)
            .clientCredentials(clientId)
            .authMode(AuthMode.CLIENT_CREDENTIALS_MTLS)
            .mtlsCertificates(clientCertPath, clientKeyPath, caCertPath);

        if (scopes) {
            builder.defaultScopes(scopes);
        }

        return builder.build(httpClient);
    }

    /**
     * Create authentication client for JWT Bearer flow
     * @param {string} serverUrl - Authentication server URL
     * @param {string} clientId - Client ID
     * @param {string} jwtSigningKeyPath - Path to JWT signing key
     * @param {string} jwtIssuer - JWT issuer
     * @param {string} jwtAudience - JWT audience
     * @param {string} [jwtAlgorithm='RS256'] - JWT algorithm
     * @param {string[]} [scopes] - Default scopes
     * @param {Object} [httpClient] - HTTP client instance
     * @returns {Object} Authentication client
     */
    static createJwtBearer(serverUrl, clientId, jwtSigningKeyPath, jwtIssuer, jwtAudience, jwtAlgorithm = 'RS256', scopes, httpClient) {
        const builder = AuthClientFactory.create()
            .serverUrl(serverUrl)
            .clientCredentials(clientId)
            .authMode(AuthMode.JWT_BEARER)
            .jwtSettings(jwtSigningKeyPath, jwtIssuer, jwtAudience, jwtAlgorithm);

        if (scopes) {
            builder.defaultScopes(scopes);
        }

        return builder.build(httpClient);
    }

    /**
     * Create authentication client for Authorization Code flow
     * @param {string} serverUrl - Authentication server URL
     * @param {string} clientId - Client ID
     * @param {string} redirectUri - Redirect URI
     * @param {string[]} [scopes] - Default scopes
     * @param {Object} [httpClient] - HTTP client instance
     * @returns {Object} Authentication client
     */
    static createAuthorizationCode(serverUrl, clientId, redirectUri, scopes, httpClient) {
        const builder = AuthClientFactory.create()
            .serverUrl(serverUrl)
            .clientCredentials(clientId) // No secret for public clients
            .authMode(AuthMode.AUTHORIZATION_CODE)
            .redirectUri(redirectUri);

        if (scopes) {
            builder.defaultScopes(scopes);
        }

        return builder.build(httpClient);
    }

    /**
     * Create authentication client for Authorization Code with PKCE flow
     * @param {string} serverUrl - Authentication server URL
     * @param {string} clientId - Client ID
     * @param {string} redirectUri - Redirect URI
     * @param {string[]} [scopes] - Default scopes
     * @param {Object} [httpClient] - HTTP client instance
     * @returns {Object} Authentication client
     */
    static createAuthorizationCodePkce(serverUrl, clientId, redirectUri, scopes, httpClient) {
        const builder = AuthClientFactory.create()
            .serverUrl(serverUrl)
            .clientCredentials(clientId) // No secret for public clients
            .authMode(AuthMode.AUTHORIZATION_CODE_PKCE)
            .redirectUri(redirectUri)
            .enablePkce(true);

        if (scopes) {
            builder.defaultScopes(scopes);
        }

        return builder.build(httpClient);
    }
}

// Legacy aliases for backward compatibility
const OAuth2AuthClientBuilder = AuthClientBuilder;
const OAuth2AuthClientFactory = AuthClientFactory;

module.exports = {
    AuthClientBuilder,
    AuthClientFactory,
    // Legacy exports
    OAuth2AuthClientBuilder,
    OAuth2AuthClientFactory
};
