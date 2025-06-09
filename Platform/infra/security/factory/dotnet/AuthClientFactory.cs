using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Factory;
using Coyote.Infra.Security.Auth.Options;
using Coyote.Infra.Security.Auth.Security;
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
/// 
/// Provides both traditional factory methods and modern options pattern support
/// with enhanced security for credential handling.
/// </summary>
public static class AuthClientFactory
{
    private static HttpFactory.IHttpClientFactory? _httpClientFactory;
    private static readonly object _lock = new object();

    /// <summary>
    /// Set the HTTP client factory (typically called during DI setup)
    /// Thread-safe operation
    /// </summary>
    public static void SetHttpClientFactory(HttpFactory.IHttpClientFactory httpClientFactory)
    {
        lock (_lock)
        {
            _httpClientFactory = httpClientFactory;
        }
    }

    #region Options Pattern Methods (Recommended)

    /// <summary>
    /// Create authentication client using Client Credentials options pattern
    /// Recommended approach for production applications
    /// </summary>
    public static IAuthClient CreateFromOptions(
        ClientCredentialsOptions options,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null)
    {
        ValidateOptions(options);
        var config = options.ToAuthClientConfig();
        var actualHttpClient = httpClient ?? GetDefaultHttpClient();
        return new AuthClient(config, actualHttpClient, tokenStorage, logger);
    }

    /// <summary>
    /// Create authentication client using mTLS options pattern
    /// Recommended approach for production applications
    /// </summary>
    public static IAuthClient CreateFromOptions(
        MtlsOptions options,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null)
    {
        ValidateOptions(options);
        var config = options.ToAuthClientConfig();
        var actualHttpClient = httpClient ?? GetDefaultHttpClient();
        return new AuthClient(config, actualHttpClient, tokenStorage, logger);
    }

    /// <summary>
    /// Create authentication client using JWT Bearer options pattern
    /// Recommended approach for production applications
    /// </summary>
    public static IAuthClient CreateFromOptions(
        JwtBearerOptions options,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null)
    {
        ValidateOptions(options);
        var config = options.ToAuthClientConfig();
        var actualHttpClient = httpClient ?? GetDefaultHttpClient();
        return new AuthClient(config, actualHttpClient, tokenStorage, logger);
    }

    /// <summary>
    /// Create authentication client using Authorization Code options pattern
    /// Recommended approach for production applications
    /// </summary>
    public static IAuthClient CreateFromOptions(
        AuthorizationCodeOptions options,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null)
    {
        ValidateOptions(options);
        var config = options.ToAuthClientConfig();
        var actualHttpClient = httpClient ?? GetDefaultHttpClient();
        return new AuthClient(config, actualHttpClient, tokenStorage, logger);
    }

    /// <summary>
    /// Create authentication client using IOptions pattern (for DI scenarios)
    /// </summary>
    public static IAuthClient CreateFromOptions<T>(
        IOptions<T> options,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null)
        where T : class
    {
        return options.Value switch
        {
            ClientCredentialsOptions clientCredOptions => CreateFromOptions(clientCredOptions, tokenStorage, logger, httpClient),
            MtlsOptions mtlsOptions => CreateFromOptions(mtlsOptions, tokenStorage, logger, httpClient),
            JwtBearerOptions jwtOptions => CreateFromOptions(jwtOptions, tokenStorage, logger, httpClient),
            AuthorizationCodeOptions authCodeOptions => CreateFromOptions(authCodeOptions, tokenStorage, logger, httpClient),
            _ => throw new ArgumentException($"Unsupported options type: {typeof(T).Name}")
        };
    }

    /// <summary>
    /// Create authentication client with secure credential provider
    /// Enhanced security for handling sensitive credentials
    /// </summary>
    public static IAuthClient CreateWithSecureCredentials(
        AuthClientConfig config,
        SecureCredentialProvider credentialProvider,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null,
        ICoyoteHttpClient? httpClient = null)
    {
        // Apply secure credentials to config
        if (credentialProvider.HasClientSecret)
        {
            config.ClientSecret = credentialProvider.GetClientSecret();
        }

        var actualHttpClient = httpClient ?? GetDefaultHttpClient();
        return new AuthClient(config, actualHttpClient, tokenStorage, logger);
    }

    #endregion

    #region Modern Factory Methods

    /// <summary>
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

    #endregion

    #region Validation and Helper Methods

    /// <summary>
    /// Validate options using data annotations
    /// </summary>
    private static void ValidateOptions(object options)
    {
        var context = new ValidationContext(options);
        var results = new List<ValidationResult>();

        if (!Validator.TryValidateObject(options, context, results, true))
        {
            var errors = string.Join(", ", results.Select(r => r.ErrorMessage));
            throw new ArgumentException($"Invalid options: {errors}");
        }
    }    
    
    /// <summary>
    /// Thread-safe HTTP client retrieval
    /// </summary>
    internal static ICoyoteHttpClient GetDefaultHttpClient()
    {
        lock (_lock)
        {
            // Use the injected HTTP client factory if available
            if (_httpClientFactory != null)
            {
                return _httpClientFactory.CreateHttpClient();
            }

            // Create a minimal service provider for HTTP client factory
            var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
            services.AddLogging();

            // Register all HTTP client implementations
            services.AddTransient<Coyote.Infra.Http.Modes.Real.RealHttpClient>();
            services.AddTransient<Coyote.Infra.Http.Modes.Mock.MockHttpClient>();
            services.AddTransient<Coyote.Infra.Http.Modes.Record.RecordingHttpClient>();
            services.AddTransient<Coyote.Infra.Http.Modes.Replay.ReplayHttpClient>();
            services.AddTransient<Coyote.Infra.Http.Modes.Simulation.SimulationHttpClient>();
            services.AddTransient<Coyote.Infra.Http.Modes.Debug.DebugHttpClient>();

            var serviceProvider = services.BuildServiceProvider();

            // Create a proper HTTP client using the platform's factory infrastructure
            var factory = new HttpFactory.HttpClientFactory(
                serviceProvider: serviceProvider,
                modeOptions: Microsoft.Extensions.Options.Options.Create(new HttpClientModeOptions
                {
                    Mode = RuntimeMode.Production
                }),
                httpOptions: Microsoft.Extensions.Options.Options.Create(new HttpClientOptions
                {
                    DefaultTimeoutMs = 30000,
                    UserAgent = "CoyoteAuth/1.0",
                    VerifyPeer = true,
                    FollowRedirects = true,
                    DefaultHeaders = new Dictionary<string, string>
                    {
                        ["Accept"] = "application/json"
                    }
                }),
                logger: Microsoft.Extensions.Logging.Abstractions.NullLogger<HttpFactory.HttpClientFactory>.Instance
            );

            return factory.CreateHttpClient();
        }
    }

    #endregion
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
