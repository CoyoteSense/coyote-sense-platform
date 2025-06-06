using System;
using System.Collections.Generic;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Factory;
using Coyote.Infra.Security.Auth;
using HttpFactory = Coyote.Infra.Http.Factory;

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
    private static HttpFactory.IHttpClientFactory? _httpClientFactory;

    /// <summary>
    /// Set the HTTP client factory (typically called during DI setup)
    /// </summary>
    public static void SetHttpClientFactory(HttpFactory.IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }
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
    {        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentials,
            ServerUrl = serverUrl,
            ClientId = clientId,
            ClientSecret = clientSecret,
            DefaultScopes = defaultScopes ?? new List<string>()
        };

        var actualHttpClient = httpClient ?? GetDefaultHttpClient();
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
    {        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentialsMtls,
            ServerUrl = serverUrl,
            ClientId = clientId,
            ClientCertPath = clientCertPath,
            ClientKeyPath = clientKeyPath,
            DefaultScopes = defaultScopes ?? new List<string>()
        };

        var actualHttpClient = httpClient ?? GetDefaultHttpClient();
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
    {        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.JwtBearer,
            ServerUrl = serverUrl,
            ClientId = clientId,
            JwtSigningKeyPath = jwtSigningKeyPath,
            JwtIssuer = jwtIssuer,
            JwtAudience = jwtAudience,
            DefaultScopes = defaultScopes ?? new List<string>()
        };

        var actualHttpClient = httpClient ?? GetDefaultHttpClient();
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
    {        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.AuthorizationCode,
            ServerUrl = serverUrl,
            ClientId = clientId,
            ClientSecret = clientSecret,
            DefaultScopes = defaultScopes ?? new List<string>()
        };

        var actualHttpClient = httpClient ?? GetDefaultHttpClient();
        return new AuthClient(config, actualHttpClient, tokenStorage, logger);
    }    /// <summary>
    /// Create authentication client with custom configuration
    /// </summary>
    public static IAuthClient CreateCustomClient(
        AuthClientConfig config,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null)
    {
        var actualHttpClient = httpClient ?? GetDefaultHttpClient();
        return new AuthClient(config, actualHttpClient, tokenStorage, logger);
    }

    /// <summary>
    /// Create authentication client builder for fluent configuration
    /// </summary>
    public static AuthClientBuilder CreateBuilder(string serverUrl, string clientId)
    {
        return new AuthClientBuilder(serverUrl, clientId);
    }

    internal static ICoyoteHttpClient GetDefaultHttpClient()
    {
        // Use the injected HTTP client factory if available
        if (_httpClientFactory != null)
        {
            return _httpClientFactory.CreateHttpClient();
        }

        // Fallback to creating a simple HTTP client with default options
        var options = new HttpClientOptions
        {
            DefaultTimeoutMs = 30000,
            UserAgent = "CoyoteAuth/1.0",
            VerifyPeer = true,
            FollowRedirects = true
        };
        
        return new SimpleHttpClient(options);
    }
}

/// <summary>
/// Simple HTTP client implementation for AuthClientFactory
/// </summary>
internal class SimpleHttpClient : BaseHttpClient
{
    public SimpleHttpClient(HttpClientOptions options) : base(options) { }    public override async Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default)
    {
        // Simple implementation using HttpClient
        using var httpClient = new HttpClient();
        httpClient.Timeout = TimeSpan.FromMilliseconds(request.TimeoutMs ?? 30000);
        
        var httpRequestMessage = new HttpRequestMessage(
            GetHttpMethod(request.Method), 
            request.Url);
            
        if (!string.IsNullOrEmpty(request.Body))
        {
            httpRequestMessage.Content = new StringContent(request.Body);
        }
        
        foreach (var header in request.Headers)
        {
            httpRequestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        
        var response = await httpClient.SendAsync(httpRequestMessage, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        
        return new HttpResponse
        {
            StatusCode = (int)response.StatusCode,
            Body = body,
            Headers = response.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value))
        };
    }
    
    public override async Task<bool> PingAsync(string url, CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await GetAsync(url, cancellationToken: cancellationToken);
            return response.IsSuccess;
        }
        catch
        {
            return false;
        }
    }
      private static System.Net.Http.HttpMethod GetHttpMethod(Coyote.Infra.Http.HttpMethod method)
    {
        return method switch
        {
            Coyote.Infra.Http.HttpMethod.Get => System.Net.Http.HttpMethod.Get,
            Coyote.Infra.Http.HttpMethod.Post => System.Net.Http.HttpMethod.Post,
            Coyote.Infra.Http.HttpMethod.Put => System.Net.Http.HttpMethod.Put,
            Coyote.Infra.Http.HttpMethod.Delete => System.Net.Http.HttpMethod.Delete,
            Coyote.Infra.Http.HttpMethod.Patch => System.Net.Http.HttpMethod.Patch,
            Coyote.Infra.Http.HttpMethod.Head => System.Net.Http.HttpMethod.Head,
            Coyote.Infra.Http.HttpMethod.Options => System.Net.Http.HttpMethod.Options,
            _ => System.Net.Http.HttpMethod.Get
        };
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
    /// Configure client secret for confidential clients (Client Credentials flow)
    /// </summary>
    public AuthClientBuilder WithClientSecret(string clientSecret)
    {
        _config.AuthMode = AuthMode.ClientCredentials;
        _config.ClientSecret = clientSecret;
        return this;
    }

    /// <summary>
    /// Configure client certificate for mTLS authentication (Client Credentials mTLS flow)
    /// </summary>
    public AuthClientBuilder WithClientCertificate(string certPath, string keyPath)
    {
        _config.AuthMode = AuthMode.ClientCredentialsMtls;
        _config.ClientCertPath = certPath;
        _config.ClientKeyPath = keyPath;
        return this;
    }

    /// <summary>
    /// Configure JWT signing for JWT Bearer flow
    /// </summary>
    public AuthClientBuilder WithJwtSigning(string signingKeyPath, string issuer, string audience)
    {
        _config.AuthMode = AuthMode.JwtBearer;
        _config.JwtSigningKeyPath = signingKeyPath;
        _config.JwtIssuer = issuer;
        _config.JwtAudience = audience;
        return this;
    }

    /// <summary>
    /// Configure Authorization Code flow (optionally with client secret)
    /// </summary>
    public AuthClientBuilder WithAuthorizationCodeFlow(string? clientSecret = null)
    {
        _config.AuthMode = AuthMode.AuthorizationCode;
        if (!string.IsNullOrEmpty(clientSecret))
            _config.ClientSecret = clientSecret;
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
        _config.VerifySsl = verify;
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
    }    /// <summary>
    /// Configure redirect URI for Authorization Code flow
    /// </summary>
    public AuthClientBuilder WithRedirectUri(string redirectUri)
    {
        _config.RedirectUri = redirectUri;
        return this;
    }

    /// <summary>
    /// Enable or disable PKCE for Authorization Code flow
    /// </summary>
    public AuthClientBuilder WithPkce(bool usePkce = true)
    {
        _config.UsePkce = usePkce;
        _config.AuthMode = usePkce ? AuthMode.AuthorizationCodePkce : AuthMode.AuthorizationCode;
        return this;
    }

    /// <summary>
    /// Configure maximum retry attempts for token operations
    /// </summary>
    public AuthClientBuilder WithMaxRetryAttempts(int attempts)
    {
        _config.MaxRetryAttempts = attempts;
        return this;
    }

    /// <summary>
    /// Configure retry delay in milliseconds for token operations
    /// </summary>
    public AuthClientBuilder WithRetryDelay(int delayMs)
    {
        _config.RetryDelayMs = delayMs;
        return this;
    }

    /// <summary>
    /// Build the authentication client
    /// </summary>
    public IAuthClient Build()
    {
        var httpClient = _httpClient ?? AuthClientFactory.GetDefaultHttpClient();
        return new AuthClient(_config, httpClient, _tokenStorage, _logger);
    }
}
