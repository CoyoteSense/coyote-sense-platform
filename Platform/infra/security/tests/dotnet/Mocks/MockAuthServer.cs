using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using WireMock.Settings;
using WireMock.Matchers;
using WireMock.Types;

namespace CoyoteSense.OAuth2.Client.Tests.Mocks;

/// <summary>
/// Mock OAuth2 server for testing OAuth2 authentication flows
/// </summary>
public class MockOAuth2Server : IDisposable
{
    private readonly WireMockServer _server;
    private readonly RSA _rsa;
    private readonly RsaSecurityKey _signingKey;
    private readonly SigningCredentials _signingCredentials;
    private readonly Dictionary<string, MockTokenInfo> _activeTokens;
    private readonly Dictionary<string, MockClientInfo> _registeredClients;
    private bool _disposed;

    public string BaseUrl => _server.Url!;
    public int Port => _server.Port!;

    public MockOAuth2Server(int? port = null)
    {
        // Initialize RSA key for JWT signing
        _rsa = RSA.Create(2048);
        _signingKey = new RsaSecurityKey(_rsa);
        _signingCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);

        // Initialize token and client storage
        _activeTokens = new Dictionary<string, MockTokenInfo>();
        _registeredClients = new Dictionary<string, MockClientInfo>();

        // Setup default test clients
        RegisterDefaultClients();

        // Start WireMock server
        var settings = new WireMockServerSettings
        {
            Port = port,
            UseSSL = false,
            StartAdminInterface = true
        };

        _server = WireMockServer.Start(settings);
        SetupEndpoints();
    }

    private void RegisterDefaultClients()
    {
        _registeredClients["test-client"] = new MockClientInfo
        {
            ClientId = "test-client",
            ClientSecret = "test-secret",
            GrantTypes = ["client_credentials", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
            Scopes = ["api.read", "api.write", "openid", "profile"]
        };

        _registeredClients["integration-test-client"] = new MockClientInfo
        {
            ClientId = "integration-test-client",
            ClientSecret = "integration-test-secret",
            GrantTypes = ["client_credentials", "authorization_code", "refresh_token"],
            Scopes = ["api.read", "api.write"]
        };
    }

    private void SetupEndpoints()
    {
        // OAuth2 Discovery Endpoint
        _server
            .Given(Request.Create().WithPath("/.well-known/openid_configuration").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody(JsonSerializer.Serialize(new
                {
                    issuer = BaseUrl,
                    token_endpoint = $"{BaseUrl}/oauth2/token",
                    introspection_endpoint = $"{BaseUrl}/oauth2/introspect",
                    revocation_endpoint = $"{BaseUrl}/oauth2/revoke",
                    jwks_uri = $"{BaseUrl}/.well-known/jwks",
                    grant_types_supported = new[] { "client_credentials", "authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer" },
                    token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
                    scopes_supported = new[] { "api.read", "api.write", "openid", "profile" },
                    response_types_supported = new[] { "code" }
                })));

        // JWKS Endpoint
        _server
            .Given(Request.Create().WithPath("/.well-known/jwks").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody(JsonSerializer.Serialize(new
                {
                    keys = new[]
                    {
                        new
                        {
                            kty = "RSA",
                            use = "sig",
                            kid = "test-key-1",
                            n = Convert.ToBase64String(_rsa.ExportParameters(false).Modulus!),
                            e = Convert.ToBase64String(_rsa.ExportParameters(false).Exponent!)
                        }
                    }
                })));

        // Token Endpoint
        _server
            .Given(Request.Create().WithPath("/oauth2/token").UsingPost())
            .RespondWith(Response.Create().WithCallback(request => HandleTokenRequest(request)));

        // Token Introspection Endpoint
        _server
            .Given(Request.Create().WithPath("/oauth2/introspect").UsingPost())
            .RespondWith(Response.Create().WithCallback(request => HandleIntrospectionRequest(request)));

        // Token Revocation Endpoint
        _server
            .Given(Request.Create().WithPath("/oauth2/revoke").UsingPost())
            .RespondWith(Response.Create().WithCallback(request => HandleRevocationRequest(request)));

        // Health Check Endpoint
        _server
            .Given(Request.Create().WithPath("/health").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody(JsonSerializer.Serialize(new { status = "healthy", timestamp = DateTimeOffset.UtcNow })));
    }

    private WireMock.ResponseMessage HandleTokenRequest(WireMock.IRequestMessage request)
    {
        try
        {
            var body = request.Body ?? string.Empty;
            var formData = ParseFormData(body);

            var grantType = formData.GetValueOrDefault("grant_type", string.Empty);
            var clientId = ExtractClientId(request, formData);
            var clientSecret = ExtractClientSecret(request, formData);

            // Validate client credentials
            if (!ValidateClient(clientId, clientSecret, grantType))
            {
                return CreateErrorResponse(HttpStatusCode.Unauthorized, "invalid_client", "Invalid client credentials");
            }

            return grantType switch
            {
                "client_credentials" => HandleClientCredentialsGrant(clientId, formData),
                "urn:ietf:params:oauth:grant-type:jwt-bearer" => HandleJwtBearerGrant(clientId, formData),
                "authorization_code" => HandleAuthorizationCodeGrant(clientId, formData),
                "refresh_token" => HandleRefreshTokenGrant(clientId, formData),
                _ => CreateErrorResponse(HttpStatusCode.BadRequest, "unsupported_grant_type", "Unsupported grant type")
            };
        }
        catch (Exception ex)
        {
            return CreateErrorResponse(HttpStatusCode.InternalServerError, "server_error", ex.Message);
        }
    }    private WireMock.ResponseMessage HandleClientCredentialsGrant(string clientId, Dictionary<string, string> formData)
    {
        var scope = formData.GetValueOrDefault("scope", "api.read");
        var token = GenerateAccessToken(clientId, scope);
        
        var tokenInfo = new MockTokenInfo
        {
            AccessToken = token,
            TokenType = "Bearer",
            ExpiresIn = 3600,
            Scope = scope,
            ClientId = clientId,
            IssuedAt = DateTimeOffset.UtcNow,
            IsActive = true
        };

        _activeTokens[token] = tokenInfo;        var response = new
        {
            access_token = token,
            token_type = "Bearer",
            expires_in = 3600,
            scope
        };        return new WireMock.ResponseMessage 
        { 
            StatusCode = (int)HttpStatusCode.OK,
            Headers = new Dictionary<string, WireMockList<string>> 
            { 
                ["Content-Type"] = new WireMockList<string>("application/json")
            },
            BodyData = new WireMock.Util.BodyData 
            { 
                BodyAsString = JsonSerializer.Serialize(response) 
            }
        };
    }

    private WireMock.ResponseMessage HandleJwtBearerGrant(string clientId, Dictionary<string, string> formData)
    {
        var assertion = formData.GetValueOrDefault("assertion", string.Empty);
        
        // Validate JWT assertion
        if (!ValidateJwtAssertion(assertion))
        {
            return CreateErrorResponse(HttpStatusCode.BadRequest, "invalid_grant", "Invalid JWT assertion");
        }

        var scope = formData.GetValueOrDefault("scope", "api.read");
        var token = GenerateAccessToken(clientId, scope);
        
        var tokenInfo = new MockTokenInfo
        {
            AccessToken = token,
            TokenType = "Bearer",
            ExpiresIn = 3600,
            Scope = scope,
            ClientId = clientId,
            IssuedAt = DateTimeOffset.UtcNow,
            IsActive = true
        };

        _activeTokens[token] = tokenInfo;        var response = new
        {
            access_token = token,
            token_type = "Bearer",
            expires_in = 3600,
            scope
        };        return new WireMock.ResponseMessage 
        { 
            StatusCode = (int)HttpStatusCode.OK,
            Headers = new Dictionary<string, WireMockList<string>> 
            { 
                ["Content-Type"] = new WireMockList<string>("application/json")
            },
            BodyData = new WireMock.Util.BodyData 
            { 
                BodyAsString = JsonSerializer.Serialize(response) 
            }
        };
    }

    private WireMock.ResponseMessage HandleAuthorizationCodeGrant(string clientId, Dictionary<string, string> formData)
    {
        var code = formData.GetValueOrDefault("code", string.Empty);
        var redirectUri = formData.GetValueOrDefault("redirect_uri", string.Empty);
        
        // Simple validation - in real implementation, this would be more robust
        if (string.IsNullOrEmpty(code) || code != "test-auth-code")
        {
            return CreateErrorResponse(HttpStatusCode.BadRequest, "invalid_grant", "Invalid authorization code");
        }

        var scope = "api.read api.write";
        var accessToken = GenerateAccessToken(clientId, scope);
        var refreshToken = GenerateRefreshToken(clientId);
        
        var tokenInfo = new MockTokenInfo
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            TokenType = "Bearer",
            ExpiresIn = 3600,
            Scope = scope,
            ClientId = clientId,
            IssuedAt = DateTimeOffset.UtcNow,
            IsActive = true
        };        _activeTokens[accessToken] = tokenInfo;        var response = new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = 3600,
            refresh_token = refreshToken,
            scope
        };

        return new WireMock.ResponseMessage 
        { 
            StatusCode = (int)HttpStatusCode.OK,
            Headers = new Dictionary<string, WireMockList<string>> 
            { 
                ["Content-Type"] = new WireMockList<string>("application/json")
            },
            BodyData = new WireMock.Util.BodyData 
            { 
                BodyAsString = JsonSerializer.Serialize(response) 
            }
        };
    }

    private WireMock.ResponseMessage HandleRefreshTokenGrant(string clientId, Dictionary<string, string> formData)
    {
        var refreshToken = formData.GetValueOrDefault("refresh_token", string.Empty);
        
        // Find the token info associated with this refresh token
        var tokenInfo = _activeTokens.Values.FirstOrDefault(t => t.RefreshToken == refreshToken && t.ClientId == clientId);
        if (tokenInfo == null)
        {
            return CreateErrorResponse(HttpStatusCode.BadRequest, "invalid_grant", "Invalid refresh token");
        }

        // Generate new access token
        var newAccessToken = GenerateAccessToken(clientId, tokenInfo.Scope);
        var newRefreshToken = GenerateRefreshToken(clientId);
        
        // Remove old token and add new one
        _activeTokens.Remove(tokenInfo.AccessToken);
        
        var newTokenInfo = new MockTokenInfo
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            TokenType = "Bearer",
            ExpiresIn = 3600,
            Scope = tokenInfo.Scope,
            ClientId = clientId,
            IssuedAt = DateTimeOffset.UtcNow,
            IsActive = true
        };

        _activeTokens[newAccessToken] = newTokenInfo;        var response = new
        {
            access_token = newAccessToken,
            token_type = "Bearer",
            expires_in = 3600,
            refresh_token = newRefreshToken,
            scope = tokenInfo.Scope
        };        return new WireMock.ResponseMessage 
        { 
            StatusCode = (int)HttpStatusCode.OK,
            Headers = new Dictionary<string, WireMockList<string>> 
            { 
                ["Content-Type"] = new WireMockList<string>("application/json")
            },
            BodyData = new WireMock.Util.BodyData 
            { 
                BodyAsString = JsonSerializer.Serialize(response) 
            }
        };
    }

    private WireMock.ResponseMessage HandleIntrospectionRequest(WireMock.IRequestMessage request)
    {
        try
        {
            var body = request.Body ?? string.Empty;
            var formData = ParseFormData(body);

            var token = formData.GetValueOrDefault("token", string.Empty);
            var clientId = ExtractClientId(request, formData);
            var clientSecret = ExtractClientSecret(request, formData);

            // Validate client credentials
            if (!ValidateClient(clientId, clientSecret, "introspection"))
            {
                return CreateErrorResponse(HttpStatusCode.Unauthorized, "invalid_client", "Invalid client credentials");
            }            var tokenInfo = _activeTokens.GetValueOrDefault(token);
            if (tokenInfo == null || !tokenInfo.IsActive)
            {
                var inactiveResponse = new { active = false };

                return new WireMock.ResponseMessage 
                { 
                    StatusCode = (int)HttpStatusCode.OK,
                    Headers = new Dictionary<string, WireMockList<string>> 
                    { 
                        ["Content-Type"] = new WireMockList<string>("application/json")
                    },
                    BodyData = new WireMock.Util.BodyData 
                    { 
                        BodyAsString = JsonSerializer.Serialize(inactiveResponse) 
                    }
                };
            }

            var activeResponse = new
            {
                active = true,
                client_id = tokenInfo.ClientId,
                scope = tokenInfo.Scope,
                token_type = tokenInfo.TokenType,
                exp = ((DateTimeOffset)tokenInfo.IssuedAt.AddSeconds(tokenInfo.ExpiresIn)).ToUnixTimeSeconds(),
                iat = tokenInfo.IssuedAt.ToUnixTimeSeconds()
            };            return new WireMock.ResponseMessage 
            { 
                StatusCode = (int)HttpStatusCode.OK,
                Headers = new Dictionary<string, WireMockList<string>> 
                { 
                    ["Content-Type"] = new WireMockList<string>("application/json")
                },
                BodyData = new WireMock.Util.BodyData 
                { 
                    BodyAsString = JsonSerializer.Serialize(activeResponse) 
                }
            };
        }
        catch (Exception ex)
        {
            return CreateErrorResponse(HttpStatusCode.InternalServerError, "server_error", ex.Message);
        }
    }

    private WireMock.ResponseMessage HandleRevocationRequest(WireMock.IRequestMessage request)
    {
        try
        {
            var body = request.Body ?? string.Empty;
            var formData = ParseFormData(body);

            var token = formData.GetValueOrDefault("token", string.Empty);
            var clientId = ExtractClientId(request, formData);
            var clientSecret = ExtractClientSecret(request, formData);

            // Validate client credentials
            if (!ValidateClient(clientId, clientSecret, "revocation"))
            {
                return CreateErrorResponse(HttpStatusCode.Unauthorized, "invalid_client", "Invalid client credentials");
            }            // Revoke the token
            if (_activeTokens.TryGetValue(token, out var tokenInfo))
            {
                tokenInfo.IsActive = false;
            }

            return new WireMock.ResponseMessage 
            { 
                StatusCode = (int)HttpStatusCode.OK,
                Headers = new Dictionary<string, WireMockList<string>> 
                { 
                    ["Content-Type"] = new WireMockList<string>("application/json")
                }
            };
        }
        catch (Exception ex)
        {
            return CreateErrorResponse(HttpStatusCode.InternalServerError, "server_error", ex.Message);
        }
    }

    private string GenerateAccessToken(string clientId, string scope)
    {
        var claims = new[]
        {
            new Claim("sub", clientId),
            new Claim("client_id", clientId),
            new Claim("scope", scope),
            new Claim("iss", BaseUrl),
            new Claim("aud", "api")
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = _signingCredentials,
            Issuer = BaseUrl,
            Audience = "api"
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private string GenerateRefreshToken(string clientId)
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[32];
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private bool ValidateClient(string clientId, string clientSecret, string grantType)
    {
        if (!_registeredClients.TryGetValue(clientId, out var client))
            return false;

        if (client.ClientSecret != clientSecret)
            return false;

        if (grantType != "introspection" && grantType != "revocation" && !client.GrantTypes.Contains(grantType))
            return false;

        return true;
    }

    private bool ValidateJwtAssertion(string assertion)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            if (!tokenHandler.CanReadToken(assertion))
                return false;

            var jwt = tokenHandler.ReadJwtToken(assertion);
            
            // Basic validation - in real implementation, this would be more comprehensive
            return jwt.ValidTo > DateTime.UtcNow;
        }
        catch
        {
            return false;
        }
    }

    private string ExtractClientId(WireMock.IRequestMessage request, Dictionary<string, string> formData)
    {
        // Try form data first
        if (formData.TryGetValue("client_id", out var clientId))
            return clientId;

        // Try Basic authentication
        if (request.Headers?.TryGetValue("Authorization", out var authHeader) == true)
        {
            var authValue = authHeader.FirstOrDefault();
            if (authValue?.StartsWith("Basic ") == true)
            {
                var encoded = authValue.Substring(6);
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                var parts = decoded.Split(':');
                if (parts.Length == 2)
                    return parts[0];
            }
        }

        return string.Empty;
    }

    private string ExtractClientSecret(WireMock.IRequestMessage request, Dictionary<string, string> formData)
    {
        // Try form data first
        if (formData.TryGetValue("client_secret", out var clientSecret))
            return clientSecret;

        // Try Basic authentication
        if (request.Headers?.TryGetValue("Authorization", out var authHeader) == true)
        {
            var authValue = authHeader.FirstOrDefault();
            if (authValue?.StartsWith("Basic ") == true)
            {
                var encoded = authValue.Substring(6);
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                var parts = decoded.Split(':');
                if (parts.Length == 2)
                    return parts[1];
            }
        }

        return string.Empty;
    }

    private Dictionary<string, string> ParseFormData(string body)
    {
        var result = new Dictionary<string, string>();
        if (string.IsNullOrEmpty(body))
            return result;

        var pairs = body.Split('&');
        foreach (var pair in pairs)
        {
            var keyValue = pair.Split('=');
            if (keyValue.Length == 2)
            {
                var key = Uri.UnescapeDataString(keyValue[0]);
                var value = Uri.UnescapeDataString(keyValue[1]);
                result[key] = value;
            }
        }

        return result;
    }    private WireMock.ResponseMessage CreateErrorResponse(HttpStatusCode statusCode, string error, string description)
    {
        var errorResponse = new
        {
            error,
            error_description = description
        };

        return new WireMock.ResponseMessage 
        { 
            StatusCode = (int)statusCode,
            Headers = new Dictionary<string, WireMockList<string>> 
            { 
                ["Content-Type"] = new WireMockList<string>("application/json")
            },
            BodyData = new WireMock.Util.BodyData 
            { 
                BodyAsString = JsonSerializer.Serialize(errorResponse) 
            }
        };
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _server?.Stop();
            _server?.Dispose();
            _rsa?.Dispose();
            _disposed = true;
        }
    }

    private class MockTokenInfo
    {
        public string AccessToken { get; set; } = string.Empty;
        public string? RefreshToken { get; set; }
        public string TokenType { get; set; } = "Bearer";
        public int ExpiresIn { get; set; }
        public string Scope { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public DateTimeOffset IssuedAt { get; set; }
        public bool IsActive { get; set; }
    }

    private class MockClientInfo
    {
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public List<string> GrantTypes { get; set; } = new();
        public List<string> Scopes { get; set; } = new();
    }
}