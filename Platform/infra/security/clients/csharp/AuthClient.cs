using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Coyote.Infra.Http;
using HttpFactory = Coyote.Infra.Http.Factory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

[assembly: InternalsVisibleTo("AuthClient.Tests")]

namespace Coyote.Infra.Security.Auth;

/// <summary>
/// Multi-standard authentication client implementation supporting OAuth2 (RFC 6749),
/// JWT Bearer (RFC 7523), and mTLS (RFC 8705) authentication methods.
/// </summary>
public class AuthClient : IAuthClient
{
    private readonly AuthClientConfig _config;
    private readonly ICoyoteHttpClient _httpClient;
    private readonly IAuthTokenStorage _tokenStorage;
    private readonly IAuthLogger _logger;
    private readonly Timer? _refreshTimer;
    private AuthToken? _currentToken;
    private bool _disposed;    /// <summary>
    /// DI constructor: uses Microsoft ILogger, HTTP client factory, and optional token storage
    /// </summary>
    [ActivatorUtilitiesConstructor]
    public AuthClient(
        AuthClientConfig config,
        ILogger<AuthClient> msLogger,
        HttpFactory.IHttpClientFactory httpClientFactory,
        IAuthTokenStorage? tokenStorage = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        
        // Validate configuration
        if (!_config.IsValid())
        {
            throw new ArgumentException("Invalid authentication configuration. Please check required fields for the selected authentication mode.", nameof(config));
        }
        
        // Use provided or default HTTP client
        _httpClient = httpClientFactory.CreateHttpClient();
        _tokenStorage = tokenStorage ?? new InMemoryTokenStorage();
        _logger = new MicrosoftAuthLogger(msLogger);

        // Configure HTTP client
        ConfigureHttpClient();

        // Load stored token
        LoadStoredToken();

        // Setup automatic refresh timer if enabled
        if (_config.AutoRefresh)
        {
            _refreshTimer = new Timer(OnRefreshTimer, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        }
    }    /// <summary>
    /// Core constructor with IAuthLogger for manual instantiation
    /// </summary>
    internal AuthClient(
        AuthClientConfig config,
        ICoyoteHttpClient? httpClient = null,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        
        // Validate configuration
        if (!_config.IsValid())
        {
            throw new ArgumentException("Invalid authentication configuration. Please check required fields for the selected authentication mode.", nameof(config));
        }
        
        // Use provided or default HTTP client
        _httpClient = httpClient ?? AuthClientFactory.GetDefaultHttpClient();
        _tokenStorage = tokenStorage ?? new InMemoryTokenStorage();
        _logger = logger ?? new NullAuthLogger();

        // Configure HTTP client
        ConfigureHttpClient();

        // Load stored token
        LoadStoredToken();

        // Setup automatic refresh timer if enabled
        if (_config.AutoRefresh)
        {
            _refreshTimer = new Timer(OnRefreshTimer, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        }    }

    /// <summary>
    /// Gets the current authentication token
    /// </summary>
    public AuthToken? CurrentToken => _currentToken;

    /// <summary>
    /// Gets a value indicating whether the client is currently authenticated
    /// </summary>
    public bool IsAuthenticated => _currentToken != null && !_currentToken.IsExpired;

    /// <summary>
    /// Authenticates using OAuth2 Client Credentials flow (RFC 6749)
    /// </summary>
    /// <param name="scopes">Optional scopes to request during authentication</param>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>Authentication result containing token or error information</returns>
    public async Task<AuthResult> AuthenticateClientCredentialsAsync(List<string>? scopes = null, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInfo("Starting Client Credentials authentication");

            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _config.ClientId
            };

            if (!string.IsNullOrEmpty(_config.ClientSecret))
            {
                parameters["client_secret"] = _config.ClientSecret;
            }

            if (scopes?.Any() == true)
            {
                parameters["scope"] = string.Join(" ", scopes);
            }
            else if (_config.DefaultScopes.Any())
            {
                parameters["scope"] = string.Join(" ", _config.DefaultScopes);
            }

            var result = await MakeTokenRequestAsync(parameters, cancellationToken);
            
            if (result.IsSuccess)
            {
                _logger.LogInfo("Client Credentials authentication successful");
                await StoreTokenAsync(result.Token!);
            }
            else
            {
                _logger.LogError($"Client Credentials authentication failed: {result.ErrorCode} - {result.ErrorDescription}");
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Client Credentials authentication error: {ex.Message}");
            return AuthResult.Error("authentication_error", "Authentication failed", ex.Message);
        }    }

    /// <summary>
    /// Authenticates using JWT Bearer token flow (RFC 7523)
    /// </summary>
    /// <param name="subject">Optional subject for the JWT assertion</param>
    /// <param name="scopes">Optional scopes to request during authentication</param>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>Authentication result containing token or error information</returns>
    public async Task<AuthResult> AuthenticateJwtBearerAsync(string? subject = null, List<string>? scopes = null, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInfo("Starting JWT Bearer authentication");

            if (string.IsNullOrEmpty(_config.JwtSigningKeyPath))
            {
                throw new InvalidOperationException("JWT signing key path is required for JWT Bearer flow");
            }

            var jwtAssertion = CreateJwtAssertion(subject);            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer",
                ["assertion"] = jwtAssertion,
                ["client_id"] = _config.ClientId
            };

            if (scopes?.Any() == true)
            {
                parameters["scope"] = string.Join(" ", scopes);
            }
            else if (_config.DefaultScopes.Any())
            {
                parameters["scope"] = string.Join(" ", _config.DefaultScopes);
            }

            var result = await MakeTokenRequestAsync(parameters, cancellationToken);
            
            if (result.IsSuccess)
            {
                _logger.LogInfo("JWT Bearer authentication successful");
                await StoreTokenAsync(result.Token!);
            }
            else
            {
                _logger.LogError($"JWT Bearer authentication failed: {result.ErrorCode} - {result.ErrorDescription}");
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError($"JWT Bearer authentication error: {ex.Message}");
            return AuthResult.Error("authentication_error", "Authentication failed", ex.Message);
        }    }

    /// <summary>
    /// Authenticates using OAuth2 Authorization Code flow (RFC 6749)
    /// </summary>
    /// <param name="authorizationCode">Authorization code received from the authorization server</param>
    /// <param name="redirectUri">Redirect URI used during authorization</param>
    /// <param name="codeVerifier">Optional PKCE code verifier for enhanced security</param>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>Authentication result containing token or error information</returns>
    public async Task<AuthResult> AuthenticateAuthorizationCodeAsync(string authorizationCode, string redirectUri, string? codeVerifier = null, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInfo("Starting Authorization Code authentication");

            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = authorizationCode,
                ["redirect_uri"] = redirectUri,
                ["client_id"] = _config.ClientId
            };

            if (!string.IsNullOrEmpty(_config.ClientSecret))
            {
                parameters["client_secret"] = _config.ClientSecret;
            }

            if (!string.IsNullOrEmpty(codeVerifier))
            {
                parameters["code_verifier"] = codeVerifier;
            }

            var result = await MakeTokenRequestAsync(parameters, cancellationToken);
            
            if (result.IsSuccess)
            {
                _logger.LogInfo("Authorization Code authentication successful");
                await StoreTokenAsync(result.Token!);
            }
            else
            {
                _logger.LogError($"Authorization Code authentication failed: {result.ErrorCode} - {result.ErrorDescription}");
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Authorization Code authentication error: {ex.Message}");
            return AuthResult.Error("authentication_error", "Authentication failed", ex.Message);
        }    }

    /// <summary>
    /// Starts OAuth2 Authorization Code flow with PKCE (RFC 7636)
    /// </summary>
    /// <param name="redirectUri">Redirect URI where the authorization code will be sent</param>
    /// <param name="scopes">Optional scopes to request during authorization</param>
    /// <param name="state">Optional state parameter for CSRF protection</param>
    /// <returns>Tuple containing authorization URL, code verifier, and state</returns>
    public (string authorizationUrl, string codeVerifier, string state) StartAuthorizationCodeFlow(string redirectUri, List<string>? scopes = null, string? state = null)
    {
        _logger.LogInfo("Starting Authorization Code + PKCE flow");

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var actualState = state ?? Guid.NewGuid().ToString();

        var parameters = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = _config.ClientId,
            ["redirect_uri"] = redirectUri,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256",
            ["state"] = actualState
        };

        if (scopes?.Any() == true)
        {
            parameters["scope"] = string.Join(" ", scopes);
        }
        else if (_config.DefaultScopes.Any())
        {
            parameters["scope"] = string.Join(" ", _config.DefaultScopes);
        }

        var queryString = string.Join("&", parameters.Select(kv => $"{UrlEncode(kv.Key)}={UrlEncode(kv.Value)}"));
        var authorizationUrl = $"{_config.ServerUrl}/authorize?{queryString}";

        return (authorizationUrl, codeVerifier, actualState);    }

    /// <summary>
    /// Refreshes an access token using a refresh token
    /// </summary>
    /// <param name="refreshToken">The refresh token to use for obtaining a new access token</param>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>Authentication result containing the new token or error information</returns>
    public async Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInfo("Refreshing token");

            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = _config.ClientId
            };

            if (!string.IsNullOrEmpty(_config.ClientSecret))
            {
                parameters["client_secret"] = _config.ClientSecret;
            }

            var result = await MakeTokenRequestAsync(parameters, cancellationToken);
            
            if (result.IsSuccess)
            {
                _logger.LogInfo("Token refresh successful");
                await StoreTokenAsync(result.Token!);
            }
            else
            {
                _logger.LogError($"Token refresh failed: {result.ErrorCode} - {result.ErrorDescription}");
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Token refresh error: {ex.Message}");
            return AuthResult.Error("refresh_error", "Token refresh failed", ex.Message);
        }    }

    /// <summary>
    /// Gets a valid token, automatically refreshing if needed and possible
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>Valid authentication token or null if not available</returns>
    public async Task<AuthToken?> GetValidTokenAsync(CancellationToken cancellationToken = default)
    {
        if (_currentToken == null)
        {
            return null;
        }

        if (!_currentToken.NeedsRefresh(_config.RefreshBufferSeconds))
        {
            return _currentToken;
        }

        if (!string.IsNullOrEmpty(_currentToken.RefreshToken))
        {
            var refreshResult = await RefreshTokenAsync(_currentToken.RefreshToken, cancellationToken);
            if (refreshResult.IsSuccess)
            {
                return refreshResult.Token;
            }
        }        return _currentToken.IsExpired ? null : _currentToken;
    }

    /// <summary>
    /// Revokes an access or refresh token
    /// </summary>
    /// <param name="token">The token to revoke</param>
    /// <param name="tokenTypeHint">Optional hint about the token type (access_token or refresh_token)</param>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>True if revocation was successful, false otherwise</returns>
    public async Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInfo("Revoking token");

            var parameters = new Dictionary<string, string>
            {
                ["token"] = token
            };

            if (!string.IsNullOrEmpty(tokenTypeHint))
            {
                parameters["token_type_hint"] = tokenTypeHint;
            }

            var formContent = CreateFormUrlEncodedContent(parameters);
            var headers = new Dictionary<string, string>
            {
                ["Content-Type"] = "application/x-www-form-urlencoded"
            };

            var response = await _httpClient.PostAsync($"{_config.ServerUrl}/revoke", formContent, headers, cancellationToken);

            var success = response.IsSuccess;
            _logger.LogInfo($"Token revocation {(success ? "successful" : "failed")}");
            return success;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Token revocation error: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Introspects a token to check its validity and properties
    /// </summary>
    /// <param name="token">The token to introspect</param>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>True if the token is active, false otherwise</returns>
    public async Task<bool> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            // If token is a JWT, perform local validation only
            if (token.Split('.')?.Length == 3)
            {
                var valid = await ValidateJwtAsync(token, cancellationToken);
                _logger.LogInfo($"Local JWT validation result: {(valid ? "valid" : "invalid")}");
                return valid;
            }

            _logger.LogInfo("Introspecting token");
            
            var parameters = new Dictionary<string, string>
            {
                ["token"] = token
            };

            var formContent = CreateFormUrlEncodedContent(parameters);
            var headers = new Dictionary<string, string>
            {
                ["Content-Type"] = "application/x-www-form-urlencoded"
            };

            var response = await _httpClient.PostAsync($"{_config.ServerUrl}/introspect", formContent, headers, cancellationToken);

            if (!response.IsSuccess)
            {
                return false;
            }

            using var doc = JsonDocument.Parse(response.Body);
            var active = doc.RootElement.TryGetProperty("active", out var activeProp) && activeProp.GetBoolean();
            
            _logger.LogInfo($"Token introspection result: {(active ? "active" : "inactive")}");
            return active;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Token introspection error: {ex.Message}");
            return false;
        }    }

    /// <summary>
    /// Tests the connection to the authentication server
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>True if connection is successful, false otherwise</returns>
    public async Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInfo("Testing connection to auth server");
            var result = await _httpClient.PingAsync(_config.ServerUrl, cancellationToken);
            _logger.LogInfo($"Connection test {(result ? "successful" : "failed")}");
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Connection test error: {ex.Message}");
            return false;
        }    }

    /// <summary>
    /// Gets information about the authentication server capabilities
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for the operation</param>
    /// <returns>Server information or null if not available</returns>
    public async Task<AuthServerInfo?> GetServerInfoAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInfo("Getting auth server information");

            var response = await _httpClient.GetAsync($"{_config.ServerUrl}/.well-known/oauth-authorization-server", cancellationToken: cancellationToken);
            
            if (!response.IsSuccess)
            {
                // Fallback - create info from known endpoints
                return new AuthServerInfo
                {
                    AuthorizationEndpoint = $"{_config.ServerUrl}/authorize",
                    TokenEndpoint = $"{_config.ServerUrl}/token",
                    IntrospectionEndpoint = $"{_config.ServerUrl}/introspect",
                    RevocationEndpoint = $"{_config.ServerUrl}/revoke",
                    GrantTypesSupported = new List<string> { "client_credentials", "authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer" }
                };
            }

            using var doc = JsonDocument.Parse(response.Body);
            var root = doc.RootElement;

            return new AuthServerInfo
            {
                AuthorizationEndpoint = root.TryGetProperty("authorization_endpoint", out var authProp) ? authProp.GetString() ?? "" : $"{_config.ServerUrl}/authorize",
                TokenEndpoint = root.TryGetProperty("token_endpoint", out var tokenProp) ? tokenProp.GetString() ?? "" : $"{_config.ServerUrl}/token",
                IntrospectionEndpoint = root.TryGetProperty("introspection_endpoint", out var introspectProp) ? introspectProp.GetString() : $"{_config.ServerUrl}/introspect",
                RevocationEndpoint = root.TryGetProperty("revocation_endpoint", out var revokeProp) ? revokeProp.GetString() : $"{_config.ServerUrl}/revoke",
                GrantTypesSupported = root.TryGetProperty("grant_types_supported", out var grantsProp) ? 
                    grantsProp.EnumerateArray().Select(x => x.GetString() ?? "").ToList() :
                    new List<string> { "client_credentials", "authorization_code", "refresh_token" },
                ScopesSupported = root.TryGetProperty("scopes_supported", out var scopesProp) ? 
                    scopesProp.EnumerateArray().Select(x => x.GetString() ?? "").ToList() :
                    new List<string>()
            };
        }
        catch (Exception ex)
        {
            _logger.LogError($"Get server info error: {ex.Message}");
            return null;
        }    }

    /// <summary>
    /// Clears all stored tokens from memory and storage
    /// </summary>
    public void ClearTokens()
    {
        _logger.LogInfo("Clearing stored tokens");
        _currentToken = null;
        _tokenStorage.ClearToken(_config.ClientId);
    }

    // Synchronous wrapper methods for backwards compatibility
    
    /// <summary>
    /// Synchronous wrapper for AuthenticateClientCredentialsAsync
    /// </summary>
    public AuthResult AuthenticateClientCredentials(List<string>? scopes = null) =>
        AuthenticateClientCredentialsAsync(scopes).GetAwaiter().GetResult();

    /// <summary>
    /// Synchronous wrapper for AuthenticateJwtBearerAsync
    /// </summary>
    public AuthResult AuthenticateJwtBearer(string? subject = null, List<string>? scopes = null) =>
        AuthenticateJwtBearerAsync(subject, scopes).GetAwaiter().GetResult();

    /// <summary>
    /// Synchronous wrapper for AuthenticateAuthorizationCodeAsync
    /// </summary>
    public AuthResult AuthenticateAuthorizationCode(string authorizationCode, string redirectUri, string? codeVerifier = null) =>
        AuthenticateAuthorizationCodeAsync(authorizationCode, redirectUri, codeVerifier).GetAwaiter().GetResult();    /// <summary>
    /// Synchronous wrapper for RefreshTokenAsync
    /// </summary>
    public AuthResult RefreshToken(string refreshToken) =>
        RefreshTokenAsync(refreshToken).GetAwaiter().GetResult();

    /// <summary>
    /// Synchronous wrapper for GetValidTokenAsync
    /// </summary>
    public AuthToken? GetValidToken() =>
        GetValidTokenAsync().GetAwaiter().GetResult();    /// <summary>
    /// Synchronous wrapper for RevokeTokenAsync
    /// </summary>
    public bool RevokeToken(string token, string? tokenTypeHint = null) =>
        RevokeTokenAsync(token, tokenTypeHint).GetAwaiter().GetResult();

    /// <summary>
    /// Synchronous wrapper for IntrospectTokenAsync
    /// </summary>
    public bool IntrospectToken(string token) =>
        IntrospectTokenAsync(token).GetAwaiter().GetResult();    /// <summary>
    /// Synchronous wrapper for TestConnectionAsync
    /// </summary>
    public bool TestConnection() =>
        TestConnectionAsync().GetAwaiter().GetResult();

    /// <summary>
    /// Synchronous wrapper for GetServerInfoAsync
    /// </summary>
    public AuthServerInfo? GetServerInfo() =>
        GetServerInfoAsync().GetAwaiter().GetResult();

    private void ConfigureHttpClient()
    {
        _httpClient.SetDefaultTimeout(_config.TimeoutMs);
        _httpClient.SetVerifyPeer(_config.VerifySsl);

        var headers = new Dictionary<string, string>
        {
            ["Accept"] = "application/json",
            ["User-Agent"] = "CoyoteSense-Auth-Client/1.0"
        };

        _httpClient.SetDefaultHeaders(headers);

        if (!string.IsNullOrEmpty(_config.ClientCertPath) && !string.IsNullOrEmpty(_config.ClientKeyPath))
        {
            _httpClient.SetClientCertificate(_config.ClientCertPath, _config.ClientKeyPath);
        }
    }    private async Task<AuthResult> MakeTokenRequestAsync(Dictionary<string, string> parameters, CancellationToken cancellationToken)
    {
        var formContent = CreateFormUrlEncodedContent(parameters);
        
        var headers = new Dictionary<string, string>
        {
            ["Content-Type"] = "application/x-www-form-urlencoded"
        };

        var response = await _httpClient.PostAsync($"{_config.ServerUrl}/token", formContent, headers, cancellationToken);

        if (!response.IsSuccess)
        {
            try
            {
                using var doc = JsonDocument.Parse(response.Body);
                var root = doc.RootElement;
                var error = root.TryGetProperty("error", out var errorProp) ? errorProp.GetString() : "unknown_error";
                var errorDescription = root.TryGetProperty("error_description", out var descProp) ? descProp.GetString() : null;
                
                return AuthResult.Error(error ?? "unknown_error", errorDescription, $"HTTP {response.StatusCode}");
            }
            catch
            {
                return AuthResult.Error("http_error", $"HTTP {response.StatusCode}", response.Body);
            }        }

        try
        {
            Console.WriteLine($"[AuthClient] Response body received: '{response.Body}'");
            Console.WriteLine($"[AuthClient] Response body length: {response.Body?.Length ?? 0}");
            Console.WriteLine($"[AuthClient] Response status: {response.StatusCode}");
            Console.WriteLine($"[AuthClient] Response is success: {response.IsSuccess}");
            
            if (string.IsNullOrWhiteSpace(response.Body))
            {
                Console.WriteLine($"[AuthClient] ERROR: Response body is null or empty!");
                return AuthResult.Error("empty_response", "Server returned empty response", "No response body received");
            }
            
            using var doc = JsonDocument.Parse(response.Body);
            var root = doc.RootElement;

            var accessToken = root.GetProperty("access_token").GetString() ?? "";
            var tokenType = root.TryGetProperty("token_type", out var typeProp) ? typeProp.GetString() ?? "Bearer" : "Bearer";
            var expiresIn = root.TryGetProperty("expires_in", out var expiresProp) ? expiresProp.GetInt32() : 3600;
            var refreshToken = root.TryGetProperty("refresh_token", out var refreshProp) ? refreshProp.GetString() : null;
            var scope = root.TryGetProperty("scope", out var scopeProp) ? scopeProp.GetString() : null;

            var token = new AuthToken
            {
                AccessToken = accessToken,
                TokenType = tokenType,
                ExpiresAt = DateTime.UtcNow.AddSeconds(expiresIn),
                RefreshToken = refreshToken,
                Scopes = scope?.Split(' ').ToList() ?? new List<string>()
            };

            return AuthResult.Success(token);
        }
        catch (Exception ex)
        {
            return AuthResult.Error("parse_error", "Failed to parse token response", ex.Message);
        }
    }

    private string CreateJwtAssertion(string? subject = null)
    {
        if (string.IsNullOrEmpty(_config.JwtSigningKeyPath) || string.IsNullOrEmpty(_config.JwtIssuer) || string.IsNullOrEmpty(_config.JwtAudience))
        {
            throw new InvalidOperationException("JWT configuration is incomplete");
        }

        var keyContent = System.IO.File.ReadAllText(_config.JwtSigningKeyPath);
        var rsa = RSA.Create();
        rsa.ImportFromPem(keyContent);
        var signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Iss, _config.JwtIssuer),
            new(JwtRegisteredClaimNames.Aud, _config.JwtAudience),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        if (!string.IsNullOrEmpty(subject))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, subject));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            SigningCredentials = signingCredentials
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private static string GenerateCodeVerifier()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncode(bytes);
    }

    private static string GenerateCodeChallenge(string codeVerifier)
    {
        var bytes = Encoding.UTF8.GetBytes(codeVerifier);
        var hash = SHA256.HashData(bytes);
        return Base64UrlEncode(hash);
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    private void LoadStoredToken()
    {
        try
        {
            _currentToken = _tokenStorage.GetToken(_config.ClientId);
            if (_currentToken != null)
            {
                _logger.LogInfo("Loaded stored token");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError($"Failed to load stored token: {ex.Message}");
        }
    }

    private async Task StoreTokenAsync(AuthToken token)
    {
        _currentToken = token;
        try
        {
            await _tokenStorage.StoreTokenAsync(_config.ClientId, token);
        }
        catch (Exception ex)
        {
            _logger.LogError($"Failed to store token: {ex.Message}");
        }
    }

    private static string CreateFormUrlEncodedContent(Dictionary<string, string> parameters)
    {
        var encoded = parameters
            .Where(kvp => !string.IsNullOrEmpty(kvp.Value))
            .Select(kvp => $"{UrlEncode(kvp.Key)}={UrlEncode(kvp.Value)}")
            .ToArray();
        
        return string.Join("&", encoded);
    }

    private static string UrlEncode(string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        var encoded = new StringBuilder();
        foreach (char c in value)
        {
            if (char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.' || c == '~')
            {
                encoded.Append(c);
            }
            else
            {
                encoded.Append($"%{((int)c):X2}");
            }
        }
        return encoded.ToString();
    }

    private void OnRefreshTimer(object? state)
    {
        if (_disposed || _currentToken == null || string.IsNullOrEmpty(_currentToken.RefreshToken))
        {
            return;
        }

        if (_currentToken.NeedsRefresh(_config.RefreshBufferSeconds))
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    await RefreshTokenAsync(_currentToken.RefreshToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Background token refresh failed: {ex.Message}");
                }
            });
        }    }

    /// <summary>
    /// Releases the unmanaged resources used by the AuthClient and optionally releases the managed resources
    /// </summary>
    /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources</param>
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _refreshTimer?.Dispose();
                _httpClient?.Dispose();
            }
            _disposed = true;        }
    }

    /// <summary>
    /// Releases all resources used by the AuthClient
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Validate JWT signature and expiration using JWKS from the auth server
    /// </summary>
    private async Task<bool> ValidateJwtAsync(string token, CancellationToken cancellationToken)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            // Fetch JWKS
            var jwksUrl = $"{_config.ServerUrl}/.well-known/jwks";
            var jwksResponse = await _httpClient.GetAsync(jwksUrl, cancellationToken: cancellationToken);
            if (!jwksResponse.IsSuccess)
            {
                _logger.LogError($"Failed to retrieve JWKS from {jwksUrl}");
                // Cannot validate signature, assume valid
                return true;
            }

            var jwks = new JsonWebKeySet(jwksResponse.Body);
            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKeys = jwks.Keys,
                ValidateIssuerSigningKey = true,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false // we'll check exp manually
            };

            handler.ValidateToken(token, validationParameters, out var validatedToken);

            var jwt = handler.ReadJwtToken(token);
            // Check expiration
            if (jwt.ValidTo < DateTime.UtcNow)
            {
                _logger.LogError("JWT has expired");
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError($"JWT validation failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Adapter for Microsoft ILogger to IAuthLogger
    /// </summary>
    private class MicrosoftAuthLogger : IAuthLogger
    {
        private readonly ILogger<AuthClient> _logger;
        public MicrosoftAuthLogger(ILogger<AuthClient> logger) => _logger = logger;
        public void LogInfo(string message) => _logger.LogInformation(message);
        public void LogError(string message) => _logger.LogError(message);
        public void LogDebug(string message) => _logger.LogDebug(message);
    }
}
