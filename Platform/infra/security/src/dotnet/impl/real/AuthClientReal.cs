using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Web;

namespace Coyote.Infra.Security.Auth.Modes.Real;

/// <summary>
/// Real authentication client implementation using HttpClient
/// </summary>
public class RealAuthClient : BaseAuthClient
{
    private readonly HttpClient _httpClient;
    private readonly new ILogger<RealAuthClient> _logger;

    public RealAuthClient(AuthClientOptions options, ILogger<RealAuthClient> logger)
        : base(options, logger)
    {
        _logger = logger;
        _httpClient = new HttpClient();
        
        // Configure base address if provided
        if (!string.IsNullOrEmpty(_options.BaseUrl))
        {
            _httpClient.BaseAddress = new Uri(_options.BaseUrl);
        }
        
        // Set default headers
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "CoyoteSense-AuthClient/1.0");
        
        LogDebug("Real auth client initialized with base URL: {BaseUrl}", _options.BaseUrl);
    }

    public override async Task<AuthResult> AuthenticateClientCredentialsAsync(List<string>? scopes = null, CancellationToken cancellationToken = default)
    {
        LogDebug("Starting Client Credentials authentication");

        try
        {
            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _options.ClientId
            };

            if (!string.IsNullOrEmpty(_options.ClientSecret))
            {
                parameters["client_secret"] = _options.ClientSecret;
            }

            if (scopes != null && scopes.Count > 0)
            {
                parameters["scope"] = string.Join(" ", scopes);
            }

            var result = await ExecuteTokenRequestAsync(parameters, cancellationToken);
            
            if (result.IsSuccess)
            {
                lock (_tokenLock)
                {
                    _currentToken = result.Token;
                }
            }

            return result;
        }        catch (Exception ex)
        {
            _logger.LogError(ex, "Client Credentials authentication failed");
            return new AuthResult
            {
                IsSuccess = false,
                ErrorDescription = ex.Message
            };
        }
    }

    public override async Task<AuthResult> AuthenticateJwtBearerAsync(string? subject = null, List<string>? scopes = null, CancellationToken cancellationToken = default)
    {
        LogDebug("Starting JWT Bearer authentication");

        try
        {
            // Generate JWT assertion
            var jwt = GenerateJwtAssertion(subject);

            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer",
                ["assertion"] = jwt
            };

            if (scopes != null && scopes.Count > 0)
            {
                parameters["scope"] = string.Join(" ", scopes);
            }

            var result = await ExecuteTokenRequestAsync(parameters, cancellationToken);
            
            if (result.IsSuccess)
            {
                lock (_tokenLock)
                {
                    _currentToken = result.Token;
                }
            }

            return result;
        }        catch (Exception ex)
        {
            _logger.LogError(ex, "JWT Bearer authentication failed");
            return new AuthResult
            {
                IsSuccess = false,
                ErrorDescription = ex.Message
            };
        }
    }

    public override async Task<AuthResult> AuthenticateAuthorizationCodeAsync(string authorizationCode, string redirectUri, string? codeVerifier = null, CancellationToken cancellationToken = default)
    {
        LogDebug("Starting Authorization Code authentication");

        try
        {
            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = authorizationCode,
                ["redirect_uri"] = redirectUri,
                ["client_id"] = _options.ClientId
            };

            if (!string.IsNullOrEmpty(_options.ClientSecret))
            {
                parameters["client_secret"] = _options.ClientSecret;
            }

            if (!string.IsNullOrEmpty(codeVerifier))
            {
                parameters["code_verifier"] = codeVerifier;
            }

            var result = await ExecuteTokenRequestAsync(parameters, cancellationToken);
            
            if (result.IsSuccess)
            {
                lock (_tokenLock)
                {
                    _currentToken = result.Token;
                }
            }

            return result;
        }        catch (Exception ex)
        {
            _logger.LogError(ex, "Authorization Code authentication failed");
            return new AuthResult
            {
                IsSuccess = false,
                ErrorDescription = ex.Message
            };
        }
    }

    public override (string authorizationUrl, string codeVerifier, string state) StartAuthorizationCodeFlow(string redirectUri, List<string>? scopes = null, string? state = null)
    {
        LogDebug("Starting Authorization Code flow setup");

        // Generate state if not provided
        if (string.IsNullOrEmpty(state))
        {
            state = GenerateRandomString(32);
        }

        // Generate PKCE parameters
        var codeVerifier = GenerateRandomString(128);
        var codeChallenge = GenerateCodeChallenge(codeVerifier);

        // Build authorization URL
        var queryParams = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = _options.ClientId,
            ["redirect_uri"] = redirectUri,
            ["state"] = state,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        };

        if (scopes != null && scopes.Count > 0)
        {
            queryParams["scope"] = string.Join(" ", scopes);
        }

        var queryString = string.Join("&", queryParams.Select(kvp => 
            $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));

        var authorizationUrl = $"{_options.AuthorizationUrl}?{queryString}";

        return (authorizationUrl, codeVerifier, state);
    }

    public override async Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        LogDebug("Starting token refresh");

        try
        {
            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = _options.ClientId
            };

            if (!string.IsNullOrEmpty(_options.ClientSecret))
            {
                parameters["client_secret"] = _options.ClientSecret;
            }

            var result = await ExecuteTokenRequestAsync(parameters, cancellationToken);
            
            if (result.IsSuccess)
            {
                lock (_tokenLock)
                {
                    _currentToken = result.Token;
                }
            }

            return result;
        }        catch (Exception ex)
        {
            _logger.LogError(ex, "Token refresh failed");
            return new AuthResult
            {
                IsSuccess = false,
                ErrorDescription = ex.Message
            };
        }
    }

    public override async Task<AuthToken?> GetValidTokenAsync(CancellationToken cancellationToken = default)
    {        lock (_tokenLock)
        {
            if (IsTokenValid())
            {
                return _currentToken;
            }
        }

        // Try to refresh if we have a refresh token (outside the lock)
        var currentToken = _currentToken;
        if (currentToken?.RefreshToken != null)
        {
            LogDebug("Token expired, attempting refresh");
            var refreshResult = await RefreshTokenAsync(currentToken.RefreshToken, cancellationToken);
            if (refreshResult.IsSuccess)
            {
                return refreshResult.Token;
            }
        }

        return null;
    }

    public override async Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
    {
        LogDebug("Revoking token");

        try
        {
            if (string.IsNullOrEmpty(_options.RevocationUrl))
            {
                _logger.LogWarning("Revocation URL not configured");
                return false;
            }

            var parameters = new Dictionary<string, string>
            {
                ["token"] = token,
                ["client_id"] = _options.ClientId
            };

            if (!string.IsNullOrEmpty(tokenTypeHint))
            {
                parameters["token_type_hint"] = tokenTypeHint;
            }

            if (!string.IsNullOrEmpty(_options.ClientSecret))
            {
                parameters["client_secret"] = _options.ClientSecret;
            }

            var content = new FormUrlEncodedContent(parameters);
            var response = await _httpClient.PostAsync(_options.RevocationUrl, content, cancellationToken);

            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token revocation failed");
            return false;
        }
    }

    public override async Task<bool> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        LogDebug("Introspecting token");

        try
        {
            if (string.IsNullOrEmpty(_options.IntrospectionUrl))
            {
                _logger.LogWarning("Introspection URL not configured");
                return false;
            }

            var parameters = new Dictionary<string, string>
            {
                ["token"] = token,
                ["client_id"] = _options.ClientId
            };

            if (!string.IsNullOrEmpty(_options.ClientSecret))
            {
                parameters["client_secret"] = _options.ClientSecret;
            }

            var content = new FormUrlEncodedContent(parameters);
            var response = await _httpClient.PostAsync(_options.IntrospectionUrl, content, cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
                var introspectionResponse = JsonSerializer.Deserialize<JsonElement>(responseContent);
                
                if (introspectionResponse.TryGetProperty("active", out var activeProperty))
                {
                    return activeProperty.GetBoolean();
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token introspection failed");
            return false;
        }
    }

    public override async Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default)
    {
        LogDebug("Testing connection to auth server");

        try
        {
            var response = await _httpClient.GetAsync(_options.TokenUrl, cancellationToken);
            return response.IsSuccessStatusCode || response.StatusCode == System.Net.HttpStatusCode.MethodNotAllowed;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Connection test failed");
            return false;
        }
    }

    public override async Task<AuthServerInfo?> GetServerInfoAsync(CancellationToken cancellationToken = default)
    {
        LogDebug("Getting server info");

        try
        {
            if (string.IsNullOrEmpty(_options.DiscoveryUrl))
            {
                return null;
            }

            var response = await _httpClient.GetAsync(_options.DiscoveryUrl, cancellationToken);
            
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                var discovery = JsonSerializer.Deserialize<JsonElement>(content);
                  return new AuthServerInfo
                {
                    TokenEndpoint = discovery.TryGetProperty("token_endpoint", out var tokenEndpoint) ? tokenEndpoint.GetString() ?? "" : "",
                    AuthorizationEndpoint = discovery.TryGetProperty("authorization_endpoint", out var authEndpoint) ? authEndpoint.GetString() ?? "" : "",
                    RevocationEndpoint = discovery.TryGetProperty("revocation_endpoint", out var revEndpoint) ? revEndpoint.GetString() : null,
                    IntrospectionEndpoint = discovery.TryGetProperty("introspection_endpoint", out var intrEndpoint) ? intrEndpoint.GetString() : null,
                    GrantTypesSupported = discovery.TryGetProperty("grant_types_supported", out var grantTypes) 
                        ? grantTypes.EnumerateArray().Select(x => x.GetString() ?? "").ToList() 
                        : new List<string>(),
                    ScopesSupported = discovery.TryGetProperty("scopes_supported", out var scopes)
                        ? scopes.EnumerateArray().Select(x => x.GetString() ?? "").ToList()
                        : new List<string>()
                };
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get server info");
            return null;
        }
    }

    public override void ClearTokens()
    {
        LogDebug("Clearing stored tokens");
        
        lock (_tokenLock)
        {
            _currentToken = null;
        }
    }

    public override AuthToken? CurrentToken
    {
        get
        {
            lock (_tokenLock)
            {
                return _currentToken;
            }
        }
    }

    public override bool IsAuthenticated => IsTokenValid();

    private async Task<AuthResult> ExecuteTokenRequestAsync(Dictionary<string, string> parameters, CancellationToken cancellationToken)
    {
        try
        {
            var content = new FormUrlEncodedContent(parameters);
            var response = await _httpClient.PostAsync(_options.TokenUrl, content, cancellationToken);
            
            var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
            
            if (response.IsSuccessStatusCode)
            {
                var tokenResponse = JsonSerializer.Deserialize<JsonElement>(responseContent);
                  var expiresInSeconds = tokenResponse.TryGetProperty("expires_in", out var expiresIn) ? expiresIn.GetInt32() : 3600;
                var scopeString = tokenResponse.TryGetProperty("scope", out var scope) ? scope.GetString() : null;
                  var token = new AuthToken
                {
                    AccessToken = tokenResponse.TryGetProperty("access_token", out var accessToken) ? accessToken.GetString() ?? "" : "",
                    TokenType = tokenResponse.TryGetProperty("token_type", out var tokenType) ? tokenType.GetString() ?? "Bearer" : "Bearer",
                    RefreshToken = tokenResponse.TryGetProperty("refresh_token", out var refreshToken) ? refreshToken.GetString() : null,
                    ExpiresAt = DateTime.UtcNow.AddSeconds(expiresInSeconds),
                    Scopes = !string.IsNullOrWhiteSpace(scopeString) ? scopeString.Split(' ').ToList() : new List<string>()
                };
                
                return new AuthResult
                {
                    IsSuccess = true,
                    Token = token
                };
            }
            else
            {
                var errorResponse = JsonSerializer.Deserialize<JsonElement>(responseContent);
                var error = errorResponse.TryGetProperty("error", out var errorProp) ? errorProp.GetString() : "unknown_error";
                var errorDescription = errorResponse.TryGetProperty("error_description", out var errorDescProp) ? errorDescProp.GetString() : response.ReasonPhrase;
                  return new AuthResult
                {
                    IsSuccess = false,
                    ErrorDescription = $"{error}: {errorDescription}"
                };
            }
        }
        catch (Exception ex)
        {
            return new AuthResult
            {
                IsSuccess = false,
                ErrorDescription = ex.Message
            };
        }
    }

    private string GenerateJwtAssertion(string? subject)
    {
        // This is a simplified JWT generation - in production, use a proper JWT library
        var header = new { alg = "none", typ = "JWT" };
        var payload = new 
        {
            iss = _options.ClientId,
            sub = subject ?? _options.ClientId,
            aud = _options.TokenUrl,
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            exp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()
        };

        var headerJson = JsonSerializer.Serialize(header);
        var payloadJson = JsonSerializer.Serialize(payload);

        var headerBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(headerJson)).TrimEnd('=');
        var payloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson)).TrimEnd('=');

        return $"{headerBase64}.{payloadBase64}.";
    }

    private string GenerateRandomString(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        var random = new Random();
        return new string(Enumerable.Repeat(chars, length)
            .Select(s => s[random.Next(s.Length)]).ToArray());
    }

    private string GenerateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _httpClient?.Dispose();
        }
        
        base.Dispose(disposing);
    }
}
