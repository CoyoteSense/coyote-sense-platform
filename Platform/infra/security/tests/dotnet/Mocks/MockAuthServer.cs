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
                })));        // Token Endpoint (OAuth2 standard path)
        _server
            .Given(Request.Create().WithPath("/oauth2/token").UsingPost())
            .RespondWith(Response.Create().WithCallback(request => HandleTokenRequest(request)));

        // Token Endpoint (AuthClient expected path)
        _server
            .Given(Request.Create().WithPath("/token").UsingPost())
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
                .WithHeader("Content-Type", "application/json").WithBody(JsonSerializer.Serialize(new { status = "healthy", timestamp = DateTimeOffset.UtcNow })));
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

            Console.WriteLine($"[MockOAuth2Server] Token request received:");
            Console.WriteLine($"  Grant Type: {grantType}");
            Console.WriteLine($"  Client ID: {clientId}");
            Console.WriteLine($"  Form Data Keys: {string.Join(", ", formData.Keys)}");

            // Validate client credentials
            if (!ValidateClient(clientId, clientSecret, grantType))
            {
                Console.WriteLine($"[MockOAuth2Server] Client validation failed for {clientId}");
                return CreateErrorResponse(HttpStatusCode.Unauthorized, "invalid_client", "Invalid client credentials");
            }
            var responseMessage = grantType switch
            {
                "client_credentials" => HandleClientCredentialsGrant(clientId, formData),
                "urn:ietf:params:oauth:grant-type:jwt-bearer" => HandleJwtBearerGrant(clientId, formData),
                "authorization_code" => HandleAuthorizationCodeGrant(clientId, formData),
                "refresh_token" => HandleRefreshTokenGrant(clientId, formData),
                _ => CreateErrorResponse(HttpStatusCode.BadRequest, "unsupported_grant_type", "Unsupported grant type")
            };

            return responseMessage;
        }
        catch (Exception ex)
        {
            return CreateErrorResponse(HttpStatusCode.InternalServerError, "server_error", ex.Message);
        }
    }

    private WireMock.ResponseMessage HandleClientCredentialsGrant(string clientId, Dictionary<string, string> formData)
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

        _activeTokens[token] = tokenInfo; var response = new
        {
            access_token = token,
            token_type = "Bearer",
            expires_in = 3600,
            scope
        }; return new WireMock.ResponseMessage
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

        // Debug: Log the JWT assertion details
        Console.WriteLine($"[MockOAuth2Server] JWT Bearer Grant Request:");
        Console.WriteLine($"  Client ID: {clientId}");
        Console.WriteLine($"  Assertion present: {!string.IsNullOrEmpty(assertion)}");
        Console.WriteLine($"  Assertion length: {assertion.Length}");
        if (!string.IsNullOrEmpty(assertion))
        {
            Console.WriteLine($"  Assertion (first 50 chars): {assertion.Substring(0, Math.Min(50, assertion.Length))}...");
        }

        // Validate JWT assertion
        if (!ValidateJwtAssertion(assertion))
        {
            Console.WriteLine($"[MockOAuth2Server] JWT validation failed");
            return CreateErrorResponse(HttpStatusCode.BadRequest, "invalid_grant", "Invalid JWT assertion");
        }
        Console.WriteLine($"[MockOAuth2Server] JWT validation succeeded");

        var scope = formData.GetValueOrDefault("scope", "api.read");
        var token = GenerateAccessToken(clientId, scope);

        Console.WriteLine($"[MockOAuth2Server] Generating access token for client '{clientId}' with scope '{scope}'");
        Console.WriteLine($"[MockOAuth2Server] Generated token: {token.Substring(0, Math.Min(20, token.Length))}...");

        var tokenInfo = new MockTokenInfo
        {
            AccessToken = token,
            TokenType = "Bearer",
            ExpiresIn = 3600,
            Scope = scope,
            ClientId = clientId,
            IssuedAt = DateTimeOffset.UtcNow,
            IsActive = true
        }; _activeTokens[token] = tokenInfo; var response = new
        {
            access_token = token,
            token_type = "Bearer",
            expires_in = 3600,
            scope
        };

        var jsonResponse = JsonSerializer.Serialize(response);
        Console.WriteLine($"[MockOAuth2Server] JWT Bearer response JSON: {jsonResponse}");
        Console.WriteLine($"[MockOAuth2Server] JSON length: {jsonResponse.Length}"); return new WireMock.ResponseMessage
        {
            StatusCode = (int)HttpStatusCode.OK,
            Headers = new Dictionary<string, WireMockList<string>>
            {
                ["Content-Type"] = new WireMockList<string>("application/json")
            },
            BodyData = new WireMock.Util.BodyData
            {
                BodyAsString = jsonResponse,
                DetectedBodyType = WireMock.Types.BodyType.String
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
        }; _activeTokens[accessToken] = tokenInfo; var response = new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = 3600,
            refresh_token = refreshToken,
            scope
        };

        var jsonResponse = JsonSerializer.Serialize(response);
        Console.WriteLine($"[MockOAuth2Server] JWT Bearer response JSON: {jsonResponse}");

        var responseMessage = new WireMock.ResponseMessage
        {
            StatusCode = (int)HttpStatusCode.OK,
            Headers = new Dictionary<string, WireMockList<string>>
            {
                ["Content-Type"] = new WireMockList<string>("application/json")
            },
            BodyData = new WireMock.Util.BodyData
            {
                BodyAsString = jsonResponse
            }
        };

        Console.WriteLine($"[MockOAuth2Server] Returning response with status: {responseMessage.StatusCode}");
        Console.WriteLine($"[MockOAuth2Server] Response headers: {string.Join(", ", responseMessage.Headers.Keys)}");
        Console.WriteLine($"[MockOAuth2Server] Response body length: {jsonResponse.Length}");

        return responseMessage;
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

        _activeTokens[newAccessToken] = newTokenInfo; var response = new
        {
            access_token = newAccessToken,
            token_type = "Bearer",
            expires_in = 3600,
            refresh_token = newRefreshToken,
            scope = tokenInfo.Scope
        }; return new WireMock.ResponseMessage
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
            }
            var tokenInfo = _activeTokens.GetValueOrDefault(token);
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
            }; return new WireMock.ResponseMessage
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
        Console.WriteLine($"[MockOAuth2Server] ValidateClient called:");
        Console.WriteLine($"  Client ID: '{clientId}'");
        Console.WriteLine($"  Client Secret: '{clientSecret}'");
        Console.WriteLine($"  Grant Type: '{grantType}'");

        if (!_registeredClients.TryGetValue(clientId, out var client))
        {
            Console.WriteLine($"[MockOAuth2Server] Client '{clientId}' not found in registered clients");
            Console.WriteLine($"[MockOAuth2Server] Available clients: {string.Join(", ", _registeredClients.Keys)}");
            return false;
        }

        Console.WriteLine($"[MockOAuth2Server] Found client: ID='{client.ClientId}', Secret='{client.ClientSecret}'");

        // JWT Bearer flow does not require client secret - the JWT assertion provides authentication
        if (grantType == "urn:ietf:params:oauth:grant-type:jwt-bearer")
        {
            Console.WriteLine($"[MockOAuth2Server] JWT Bearer flow - skipping client secret validation");
        }
        else if (client.ClientSecret != clientSecret)
        {
            Console.WriteLine($"[MockOAuth2Server] Client secret mismatch! Expected: '{client.ClientSecret}', Got: '{clientSecret}'");
            return false;
        }

        if (grantType != "introspection" && grantType != "revocation" && !client.GrantTypes.Contains(grantType))
        {
            Console.WriteLine($"[MockOAuth2Server] Grant type '{grantType}' not allowed for client. Allowed: {string.Join(", ", client.GrantTypes)}");
            return false;
        }

        Console.WriteLine($"[MockOAuth2Server] Client validation successful for '{clientId}'");
        return true;
    }
    private bool ValidateJwtAssertion(string assertion)
    {
        try
        {
            Console.WriteLine($"[MockOAuth2Server] Validating JWT assertion...");

            var tokenHandler = new JwtSecurityTokenHandler();
            if (!tokenHandler.CanReadToken(assertion))
            {
                Console.WriteLine($"[MockOAuth2Server] JWT validation failed: Cannot read token");
                return false;
            }

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _signingKey,
                ValidateIssuer = false, // Skip issuer validation for test
                ValidateAudience = false, // Skip audience validation for test
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            var principal = tokenHandler.ValidateToken(assertion, validationParameters, out var validatedToken);
            Console.WriteLine($"[MockOAuth2Server] JWT validation succeeded");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MockOAuth2Server] JWT validation failed with exception: {ex.Message}");
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
        Console.WriteLine($"[MockOAuth2Server] ExtractClientSecret called:");

        // Try form data first
        if (formData.TryGetValue("client_secret", out var clientSecret))
        {
            Console.WriteLine($"[MockOAuth2Server] Found client_secret in form data: '{clientSecret}'");
            return clientSecret;
        }

        // Try Basic authentication
        if (request.Headers?.TryGetValue("Authorization", out var authHeader) == true)
        {
            var authValue = authHeader.FirstOrDefault();
            Console.WriteLine($"[MockOAuth2Server] Authorization header: '{authValue}'");
            if (authValue?.StartsWith("Basic ") == true)
            {
                var encoded = authValue.Substring(6);
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                var parts = decoded.Split(':');
                if (parts.Length == 2)
                {
                    Console.WriteLine($"[MockOAuth2Server] Extracted client_secret from Basic auth: '{parts[1]}'");
                    return parts[1];
                }
            }
        }

        Console.WriteLine($"[MockOAuth2Server] No client_secret found - returning empty string");
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
    }
    private WireMock.ResponseMessage CreateErrorResponse(HttpStatusCode statusCode, string error, string description)
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

    /// <summary>
    /// Exports the server's RSA private key as PEM for JWT signing
    /// </summary>
    public async Task<string> ExportRSAPrivateKeyAsync()
    {
        var keyPath = Path.Combine(Path.GetTempPath(), $"mock-server-jwt-key-{Guid.NewGuid()}.pem");
        var privateKey = _rsa.ExportRSAPrivateKeyPem();
        await File.WriteAllTextAsync(keyPath, privateKey);
        return keyPath;
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