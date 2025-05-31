using System;
using System.Collections.Generic;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Factory;
using Coyote.Infra.Security.Auth;

namespace Coyote.Infra.Security.Auth;

/// <summary>
/// Authentication client factory
/// Supports multiple authentication standards:
/// - OAuth2 Client Credentials (RFC 6749)
/// - OAuth2 Authorization Code (RFC 6749) 
/// - OAuth2 + PKCE (RFC 7636)
/// - JWT Bearer (RFC 7523)
/// - mTLS Client Credentials (RFC 8705)
/// </summary>
public static class AuthClientFactory
{
    /// <summary>
    /// Create authentication client for Client Credentials flow
    /// </summary>
    public static IAuthClient CreateClientCredentialsClient(
        string serverUrl,
        string clientId,
        string clientSecret,
        List<string>? defaultScopes = null,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null)
    {
        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentials,
            ServerUrl = serverUrl,
            ClientId = clientId,
            ClientSecret = clientSecret,
            DefaultScopes = defaultScopes ?? new List<string>()
        };

        var actualHttpClient = httpClient ?? CreateDefaultHttpClient();
        return new AuthClient(config, actualHttpClient, tokenStorage, logger);
    }

    /// <summary>
    /// Create authentication client for Client Credentials flow with mTLS
    /// </summary>
    public static IAuthClient CreateMtlsClient(
        string serverUrl,
        string clientId,
        string clientCertPath,
        string clientKeyPath,
        List<string>? defaultScopes = null,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null)
    {
        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentialsMtls,
            ServerUrl = serverUrl,
            ClientId = clientId,
            ClientCertPath = clientCertPath,
            ClientKeyPath = clientKeyPath,
            DefaultScopes = defaultScopes ?? new List<string>()
        };

        var actualHttpClient = httpClient ?? CreateDefaultHttpClient();
        return new AuthClient(config, actualHttpClient, tokenStorage, logger);
    }

    /// <summary>
    /// Create authentication client for JWT Bearer flow
    /// </summary>
    public static IAuthClient CreateJwtBearerClient(
        string serverUrl,
        string clientId,
        string jwtSigningKeyPath,
        string jwtIssuer,
        string jwtAudience,
        List<string>? defaultScopes = null,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null)
    {
        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.JwtBearer,
            ServerUrl = serverUrl,
            ClientId = clientId,
            JwtSigningKeyPath = jwtSigningKeyPath,
            JwtIssuer = jwtIssuer,
            JwtAudience = jwtAudience,
            DefaultScopes = defaultScopes ?? new List<string>()
        };

        var actualHttpClient = httpClient ?? CreateDefaultHttpClient();
        return new AuthClient(config, actualHttpClient, tokenStorage, logger);
    }

    /// <summary>
    /// Create authentication client for Authorization Code flow
    /// </summary>
    public static IAuthClient CreateAuthorizationCodeClient(
        string serverUrl,
        string clientId,
        string? clientSecret = null,
        List<string>? defaultScopes = null,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null)
    {
        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.AuthorizationCode,
            ServerUrl = serverUrl,
            ClientId = clientId,
            ClientSecret = clientSecret,
            DefaultScopes = defaultScopes ?? new List<string>()
        };

        var actualHttpClient = httpClient ?? CreateDefaultHttpClient();
        return new AuthClient(config, actualHttpClient, tokenStorage, logger);
    }

    /// <summary>
    /// Create authentication client with custom configuration
    /// </summary>
    public static IAuthClient CreateCustomClient(
        AuthClientConfig config,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null)
    {
        var actualHttpClient = httpClient ?? CreateDefaultHttpClient();
        return new AuthClient(config, actualHttpClient, tokenStorage, logger);
    }

    /// <summary>
    /// Create authentication client builder for fluent configuration
    /// </summary>
    public static AuthClientBuilder CreateBuilder(string serverUrl, string clientId)
    {
        return new AuthClientBuilder(serverUrl, clientId);
    }

    private static ICoyoteHttpClient CreateDefaultHttpClient()
    {
        var factory = new HttpClientFactory();
        return factory.CreateHttpClient();
    }
}

/// <summary>
/// Authentication client builder for fluent configuration
/// </summary>
public class AuthClientBuilder
{
    private readonly AuthClientConfig _config;
    private IAuthTokenStorage? _tokenStorage;
    private IAuthLogger? _logger;
    private ICoyoteHttpClient? _httpClient;

    internal AuthClientBuilder(string serverUrl, string clientId)
    {
        _config = new AuthClientConfig
        {
            ServerUrl = serverUrl,
            ClientId = clientId
        };
    }

    /// <summary>
    /// Configure client secret for confidential clients
    /// </summary>
    public AuthClientBuilder WithClientSecret(string clientSecret)
    {
        _config.ClientSecret = clientSecret;
        return this;
    }

    /// <summary>
    /// Configure client certificate for mTLS authentication
    /// </summary>
    public AuthClientBuilder WithClientCertificate(string certPath, string keyPath)
    {
        _config.ClientCertPath = certPath;
        _config.ClientKeyPath = keyPath;
        return this;
    }

    /// <summary>
    /// Configure JWT signing for JWT Bearer flow
    /// </summary>
    public AuthClientBuilder WithJwtSigning(string signingKeyPath, string issuer, string audience)
    {
        _config.JwtSigningKeyPath = signingKeyPath;
        _config.JwtIssuer = issuer;
        _config.JwtAudience = audience;
        return this;
    }

    /// <summary>
    /// Configure default scopes
    /// </summary>
    public AuthClientBuilder WithDefaultScopes(params string[] scopes)
    {
        _config.DefaultScopes = new List<string>(scopes);
        return this;
    }

    /// <summary>
    /// Configure automatic token refresh
    /// </summary>
    public AuthClientBuilder WithAutoRefresh(bool enabled = true, int bufferSeconds = 300)
    {
        _config.AutoRefresh = enabled;
        _config.RefreshBufferSeconds = bufferSeconds;
        return this;
    }

    /// <summary>
    /// Configure HTTP timeout
    /// </summary>
    public AuthClientBuilder WithTimeout(int timeoutMs)
    {
        _config.TimeoutMs = timeoutMs;
        return this;
    }

    /// <summary>
    /// Configure SSL verification
    /// </summary>
    public AuthClientBuilder WithSslVerification(bool verify)
    {
        _config.VerifyPeer = verify;
        return this;
    }

    /// <summary>
    /// Configure token storage
    /// </summary>
    public AuthClientBuilder WithTokenStorage(IAuthTokenStorage tokenStorage)
    {
        _tokenStorage = tokenStorage;
        return this;
    }

    /// <summary>
    /// Configure logger
    /// </summary>
    public AuthClientBuilder WithLogger(IAuthLogger logger)
    {
        _logger = logger;
        return this;
    }

    /// <summary>
    /// Configure HTTP client
    /// </summary>
    public AuthClientBuilder WithHttpClient(ICoyoteHttpClient httpClient)
    {
        _httpClient = httpClient;
        return this;
    }

    /// <summary>
    /// Build the authentication client
    /// </summary>
    public IAuthClient Build()
    {
        var httpClient = _httpClient ?? AuthClientFactory.CreateDefaultHttpClient();
        return new AuthClient(_config, httpClient, _tokenStorage, _logger);
    }
}

// Legacy aliases for backward compatibility
public static class AuthClientFactory
{
    public static IAuthClient CreateClientCredentialsClient(
        string serverUrl,
        string clientId,
        string clientSecret,
        List<string>? defaultScopes = null,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null) =>
        AuthClientFactory.CreateClientCredentialsClient(serverUrl, clientId, clientSecret, defaultScopes, tokenStorage, logger, httpClient);

    public static IAuthClient CreateMtlsClient(
        string serverUrl,
        string clientId,
        string clientCertPath,
        string clientKeyPath,
        List<string>? defaultScopes = null,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null) =>
        AuthClientFactory.CreateMtlsClient(serverUrl, clientId, clientCertPath, clientKeyPath, defaultScopes, tokenStorage, logger, httpClient);

    public static IAuthClient CreateJwtBearerClient(
        string serverUrl,
        string clientId,
        string jwtSigningKeyPath,
        string jwtIssuer,
        string jwtAudience,
        List<string>? defaultScopes = null,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null) =>
        AuthClientFactory.CreateJwtBearerClient(serverUrl, clientId, jwtSigningKeyPath, jwtIssuer, jwtAudience, defaultScopes, tokenStorage, logger, httpClient);

    public static IAuthClient CreateAuthorizationCodeClient(
        string serverUrl,
        string clientId,
        string? clientSecret = null,
        List<string>? defaultScopes = null,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null) =>
        AuthClientFactory.CreateAuthorizationCodeClient(serverUrl, clientId, clientSecret, defaultScopes, tokenStorage, logger, httpClient);

    public static IAuthClient CreateCustomClient(
        AuthClientConfig config,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null) =>
        AuthClientFactory.CreateCustomClient(config, tokenStorage, logger, httpClient);

    public static AuthClientBuilder CreateBuilder(string serverUrl, string clientId) =>
        AuthClientFactory.CreateBuilder(serverUrl, clientId);
}

public class OAuth2ClientBuilder : AuthClientBuilder
{
    internal OAuth2ClientBuilder(string serverUrl, string clientId) : base(serverUrl, clientId) { }
}
