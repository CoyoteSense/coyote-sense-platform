using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Coyote.Infra.Http;

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
    private bool _disposed;    public AuthClient(
        AuthClientConfig config,
        ICoyoteHttpClient httpClient,
        IAuthTokenStorage? tokenStorage = null,
        IAuthLogger? logger = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        
        // Validate configuration
        if (!_config.IsValid())
        {
            throw new ArgumentException("Invalid authentication configuration. Please check required fields for the selected authentication mode.", nameof(config));
        }
        
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
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
        }
    }

    public AuthToken? CurrentToken => _currentToken;

    public bool IsAuthenticated => _currentToken != null && !_currentToken.IsExpired;

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
        }
    }

    public async Task<AuthResult> AuthenticateJwtBearerAsync(string? subject = null, List<string>? scopes = null, CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInfo("Starting JWT Bearer authentication");

            if (string.IsNullOrEmpty(_config.JwtSigningKeyPath))
            {
                throw new InvalidOperationException("JWT signing key path is required for JWT Bearer flow");
            }

            var jwtAssertion = CreateJwtAssertion(subject);

            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer",
                ["assertion"] = jwtAssertion
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
        }
    }

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
        }
    }

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

        return (authorizationUrl, codeVerifier, actualState);
    }

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
        }
    }

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
        }

        return _currentToken.IsExpired ? null : _currentToken;
    }    public async Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
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
    }    public async Task<bool> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
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
        }
    }

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
        }
    }

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
        }
    }

    public void ClearTokens()
    {
        _logger.LogInfo("Clearing stored tokens");
        _currentToken = null;
        _tokenStorage.ClearToken(_config.ClientId);
    }

    // Synchronous wrapper methods
    public AuthResult AuthenticateClientCredentials(List<string>? scopes = null) =>
        AuthenticateClientCredentialsAsync(scopes).GetAwaiter().GetResult();

    public AuthResult AuthenticateJwtBearer(string? subject = null, List<string>? scopes = null) =>
        AuthenticateJwtBearerAsync(subject, scopes).GetAwaiter().GetResult();

    public AuthResult AuthenticateAuthorizationCode(string authorizationCode, string redirectUri, string? codeVerifier = null) =>
        AuthenticateAuthorizationCodeAsync(authorizationCode, redirectUri, codeVerifier).GetAwaiter().GetResult();

    public AuthResult RefreshToken(string refreshToken) =>
        RefreshTokenAsync(refreshToken).GetAwaiter().GetResult();

    public AuthToken? GetValidToken() =>
        GetValidTokenAsync().GetAwaiter().GetResult();

    public bool RevokeToken(string token, string? tokenTypeHint = null) =>
        RevokeTokenAsync(token, tokenTypeHint).GetAwaiter().GetResult();

    public bool IntrospectToken(string token) =>
        IntrospectTokenAsync(token).GetAwaiter().GetResult();

    public bool TestConnection() =>
        TestConnectionAsync().GetAwaiter().GetResult();

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
            }
        }

        try
        {
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
        }
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _refreshTimer?.Dispose();
                _httpClient?.Dispose();
            }
            _disposed = true;
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}
