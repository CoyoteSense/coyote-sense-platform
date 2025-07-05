using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Http;

namespace Coyote.Infra.Security.Tests.TestHelpers
{
    /// <summary>
    /// Mock HTTP client for OAuth2 authentication testing
    /// Implements ICoyoteHttpClient interface with pre-configured responses for OAuth2 endpoints
    /// </summary>
    public class MockOAuth2HttpClient : ICoyoteHttpClient
    {
        private readonly ILogger<MockOAuth2HttpClient>? _logger;
        private readonly Dictionary<string, IHttpResponse> _predefinedResponses = new();
        private readonly List<IHttpRequest> _recordedRequests = new();
        private readonly HashSet<string> _revokedTokens = new();
        private readonly Dictionary<string, Exception> _exceptionMap = new();
        private readonly Dictionary<string, List<DateTime>> _requestCounts = new();
        private bool _recordRequests = true;
        private bool _disposed;
        private const int RateLimitThreshold = 3; // Allow max 3 requests per second

        /// <summary>
        /// Create a new MockOAuth2HttpClient with optional logging
        /// </summary>
        public MockOAuth2HttpClient(ILogger<MockOAuth2HttpClient>? logger = null)
        {
            _logger = logger;

            // Set up default successful OAuth2 token response
            SetupDefaultOAuth2Responses();
        }

        /// <summary>
        /// Execute a request (main method that all other methods call)
        /// </summary>
        public Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));

            // Check for cancellation at the start
            cancellationToken.ThrowIfCancellationRequested();

            // Simulate SSL certificate failures for certain domains
            if (request.Url.Contains("self-signed.badssl.com") ||
                request.Url.Contains("expired.badssl.com") ||
                request.Url.Contains("wrong.host.badssl.com"))
            {
                throw new System.Net.Http.HttpRequestException(
                    "SSL certificate verification failed: The remote certificate is invalid according to the validation procedure.");
            }

            // Check rate limiting for repeated failed requests with invalid credentials
            if (request.Url.Contains("/token") && HasInvalidCredentials(request.Body) && IsRateLimited(request.Url))
            {
                var rateLimitResponse = new
                {
                    error = "invalid_client",
                    error_description = "Rate limit exceeded: Too many authentication attempts"
                };
                var rateLimitJson = JsonSerializer.Serialize(rateLimitResponse);
                return Task.FromResult(CreateResponse(429, rateLimitJson, "application/json"));
            }            // Log all incoming requests at INFO level to ensure they're visible
            Console.WriteLine($"[MockHttpClient] ExecuteAsync called: {request.Method} {request.Url}");
            _logger?.LogInformation("MockHttpClient ExecuteAsync: {Method} {Url}", request.Method, request.Url);
            
            // Check for cancellation before processing
            cancellationToken.ThrowIfCancellationRequested();            // Always log request body for debugging (with sensitive data redacted)
            if (!string.IsNullOrEmpty(request.Body))
            {
                var safeBody = RedactSensitiveData(request.Body);
                Console.WriteLine($"[MockHttpClient] Request body: {safeBody}");
                _logger?.LogInformation("Request body: {Body}", safeBody);
            }

            // Check if an exception should be thrown for this URL
            if (_exceptionMap.TryGetValue(request.Url, out var exception))
            {
                Console.WriteLine($"[MockHttpClient] Throwing configured exception for URL: {request.Url}");
                _logger?.LogDebug("Throwing configured exception for URL: {Url}", request.Url);
                throw exception;
            }            // Record the request if enabled            if (_recordRequests)
            {
                _recordedRequests.Add(request);
                _logger?.LogDebug("Recorded request: {Method} {Url}", request.Method, request.Url);
            }

            // Look for predefined response matching this URL exactly
            if (_predefinedResponses.TryGetValue(request.Url, out var exactResponse))
            {
                _logger?.LogDebug("Found exact match for URL: {Url}", request.Url);
                return Task.FromResult(exactResponse);
            }            // Try pattern matching for token endpoints
            if (request.Url.Contains("/oauth2/token") ||
                request.Url.Contains("/oauth/token") ||
                request.Url.Contains("/connect/token") ||
                request.Url.EndsWith("/token"))
            {
                Console.WriteLine($"[MockHttpClient] OAuth2 token endpoint detected: {request.Url}");
                _logger?.LogDebug("OAuth2 token endpoint detected: {Url}", request.Url);

                // Always handle token requests through HandleTokenRequest to validate credentials
                // Don't use predefined responses that bypass credential validation
                return HandleTokenRequest(request);
            }// Try pattern matching for discovery endpoints
            if (request.Url.Contains("/.well-known/openid_configuration") ||
                request.Url.Contains("/.well-known/openid-configuration") ||
                request.Url.Contains("/.well-known/oauth-authorization-server"))
            {
                _logger?.LogDebug("OAuth2 discovery endpoint detected: {Url}", request.Url);
                return HandleDiscoveryRequest(request);
            }

            // Try pattern matching for JWKS endpoints
            if (request.Url.Contains("/.well-known/jwks"))
            {
                _logger?.LogDebug("JWKS endpoint detected: {Url}", request.Url);                return HandleJwksRequest(request);
            }

            // Try pattern matching for introspection endpoints
            if (request.Url.Contains("/introspect"))
            {
                Console.WriteLine($"[MockHttpClient] OAuth2 introspection endpoint detected: {request.Url}");
                _logger?.LogDebug("OAuth2 introspection endpoint detected: {Url}", request.Url);

                // Check if there's a predefined response for this exact introspection URL first
                if (_predefinedResponses.TryGetValue(request.Url, out var exactIntrospectResponse))
                {
                    Console.WriteLine($"[MockHttpClient] Found exact predefined response for introspection URL: {request.Url}");
                    _logger?.LogDebug("Found exact predefined response for introspection URL: {Url}", request.Url);
                    return Task.FromResult(exactIntrospectResponse);
                }

                return HandleIntrospectionRequest(request);
            }

            // Try pattern matching for revocation endpoints
            if (request.Url.Contains("/revoke"))
            {
                Console.WriteLine($"[MockHttpClient] OAuth2 revocation endpoint detected: {request.Url}");
                _logger?.LogDebug("OAuth2 revocation endpoint detected: {Url}", request.Url);
                return HandleRevocationRequest(request);
            }

            // Default response if no matches
            Console.WriteLine($"[MockHttpClient] No predefined response for URL: {request.Url}");
            _logger?.LogWarning("No predefined response for URL: {Url}", request.Url);
            return Task.FromResult(CreateResponse(404, "Not Found", "text/plain"));
        }

        public Task<IHttpResponse> GetAsync(string url, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
        {
            var request = CreateRequest();
            request.Url = url;
            request.Method = Coyote.Infra.Http.HttpMethod.Get;

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    request.Headers[header.Key] = header.Value;
                }
            }

            return ExecuteAsync(request, cancellationToken);
        }

        public Task<IHttpResponse> PostAsync(string url, string? body = null, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
        {
            var request = CreateRequest();
            request.Url = url;
            request.Method = Coyote.Infra.Http.HttpMethod.Post;
            request.Body = body;

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    request.Headers[header.Key] = header.Value;
                }
            }

            return ExecuteAsync(request, cancellationToken);
        }

        public Task<IHttpResponse> PostJsonAsync<T>(string url, T content, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
        {
            var request = CreateRequest();
            request.Url = url;
            request.Method = Coyote.Infra.Http.HttpMethod.Post;
            request.SetJsonBody(content);

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    request.Headers[header.Key] = header.Value;
                }
            }

            return ExecuteAsync(request, cancellationToken);
        }

        public Task<IHttpResponse> PutAsync(string url, string? body = null, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
        {
            var request = CreateRequest();
            request.Url = url;
            request.Method = Coyote.Infra.Http.HttpMethod.Put;
            request.Body = body;

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    request.Headers[header.Key] = header.Value;
                }
            }

            return ExecuteAsync(request, cancellationToken);
        }

        public Task<IHttpResponse> PutJsonAsync<T>(string url, T content, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
        {
            var request = CreateRequest();
            request.Url = url;
            request.Method = Coyote.Infra.Http.HttpMethod.Put;
            request.SetJsonBody(content);

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    request.Headers[header.Key] = header.Value;
                }
            }

            return ExecuteAsync(request, cancellationToken);
        }

        public Task<IHttpResponse> DeleteAsync(string url, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
        {
            var request = CreateRequest();
            request.Url = url;
            request.Method = Coyote.Infra.Http.HttpMethod.Delete;

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    request.Headers[header.Key] = header.Value;
                }
            }

            return ExecuteAsync(request, cancellationToken);
        }

        public Task<IHttpResponse> PatchAsync(string url, string? body = null, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
        {
            var request = CreateRequest();
            request.Url = url;
            request.Method = Coyote.Infra.Http.HttpMethod.Patch;
            request.Body = body;

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    request.Headers[header.Key] = header.Value;
                }
            }

            return ExecuteAsync(request, cancellationToken);
        }

        public void SetDefaultTimeout(int timeoutMs)
        {
            // No-op for mock
        }

        public void SetDefaultHeaders(IReadOnlyDictionary<string, string> headers)
        {
            // No-op for mock
        }

        public void SetClientCertificate(string certPath, string keyPath)
        {
            // No-op for mock
        }

        public void SetCACertificate(string caPath)
        {
            // No-op for mock
        }

        public void SetVerifyPeer(bool verify)
        {
            // No-op for mock
        }
        public async Task<bool> PingAsync(string url, CancellationToken cancellationToken = default)
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

        public void Dispose()
        {
            if (!_disposed)
            {
                _predefinedResponses.Clear();
                _recordedRequests.Clear();
                _revokedTokens.Clear();
                _exceptionMap.Clear();
                _requestCounts.Clear();
                _disposed = true;
            }
        }


        /// <summary>
        /// Set up a predefined response for a specific URL
        /// </summary>
        public void SetPredefinedResponse(string url, IHttpResponse response)
        {
            _predefinedResponses[url] = response;
            _logger?.LogDebug("Set predefined response for URL: {Url}", url);
        }

        /// <summary>
        /// Set up a predefined response for a specific URL
        /// </summary>
        public void SetPredefinedResponse(string url, int statusCode, string body, string contentType = "application/json")
        {
            _predefinedResponses[url] = CreateResponse(statusCode, body, contentType);
            _logger?.LogDebug("Set predefined response for URL: {Url} with status {StatusCode}", url, statusCode);
        }

        /// <summary>
        /// Configure an exception to be thrown for a specific URL
        /// </summary>
        public void SetExceptionForUrl(string url, Exception exception)
        {
            _exceptionMap[url] = exception;
            _logger?.LogDebug("Set exception for URL: {Url}", url);
        }

        /// <summary>
        /// Get all recorded requests (useful for testing)
        /// </summary>
        public List<IHttpRequest> GetRecordedRequests()
        {
            return new List<IHttpRequest>(_recordedRequests);
        }

        /// <summary>
        /// Clear all recorded requests
        /// </summary>
        public void ClearRecordedRequests()
        {
            _recordedRequests.Clear();
        }

        /// <summary>
        /// Enable or disable request recording
        /// </summary>
        public void SetRecordRequests(bool record)
        {
            _recordRequests = record;
        }

        /// <summary>
        /// Add a token to the revoked list
        /// </summary>
        public void RevokeToken(string token)
        {
            _revokedTokens.Add(token);
        }

        /// <summary>
        /// Clear all predefined responses
        /// </summary>
        public void ClearPredefinedResponses()
        {
            _predefinedResponses.Clear();
        }

        /// <summary>
        /// Clear all exceptions
        /// </summary>
        public void ClearExceptions()
        {
            _exceptionMap.Clear();
        }


        private Task<IHttpResponse> HandleTokenRequest(IHttpRequest request)
        {
            // Parse form data or check JSON body to determine grant type
            string grantType = GetGrantTypeFromRequest(request);

            _logger?.LogDebug("Handling token request with grant type: {GrantType}", grantType);
            _logger?.LogDebug("Request URL: {Url}", request.Url);
            _logger?.LogDebug("Request Body: {Body}", SanitizeRequestBody(request.Body));

            // Debug: Log the request body to see what credentials are being sent
            Console.WriteLine($"[MockHttpClient DEBUG] Raw request body: {request.Body}");
            Console.WriteLine($"[MockHttpClient DEBUG] HasInvalidCredentials check: {HasInvalidCredentials(request.Body)}");

            // Check for invalid credentials and return error
            if (HasInvalidCredentials(request.Body))
            {
                Console.WriteLine($"[MockHttpClient DEBUG] Invalid credentials detected, returning 401 error");
                var errorResponse = new
                {
                    error = "invalid_client",
                    error_description = "Authentication failed"
                };
                var errorJson = JsonSerializer.Serialize(errorResponse);
                return Task.FromResult(CreateResponse(401, errorJson, "application/json"));
            }

            Console.WriteLine($"[MockHttpClient DEBUG] Credentials appear valid, proceeding with normal flow");

            // Return appropriate response based on grant type
            switch (grantType)
            {
                case "client_credentials":
                    _logger?.LogDebug("Returning client credentials response");
                    return Task.FromResult(CreateClientCredentialsResponse());

                case "password":
                    _logger?.LogDebug("Returning password grant response");
                    return Task.FromResult(CreatePasswordGrantResponse());

                case "refresh_token":
                    _logger?.LogDebug("Returning refresh token response");
                    return Task.FromResult(CreateRefreshTokenResponse());

                case "authorization_code":
                    _logger?.LogDebug("Returning authorization code response");
                    return Task.FromResult(CreateAuthorizationCodeResponse());

                default:
                    _logger?.LogWarning("Unsupported grant type: {GrantType}", grantType);
                    return Task.FromResult(CreateErrorResponse("unsupported_grant_type",
                        "The authorization grant type is not supported"));
            }
        }

        private string GetGrantTypeFromRequest(IHttpRequest request)
        {
            // Try to extract from form data in body
            if (!string.IsNullOrEmpty(request.Body))
            {
                // Check if it's form URL encoded
                if (request.Headers.TryGetValue("Content-Type", out var contentType) && contentType.Contains("application/x-www-form-urlencoded"))
                {
                    var pairs = request.Body.Split('&');
                    foreach (var pair in pairs)
                    {
                        var parts = pair.Split('=');
                        if (parts.Length == 2 && parts[0] == "grant_type")
                        {
                            return System.Web.HttpUtility.UrlDecode(parts[1]);
                        }
                    }
                }

                // Try JSON parsing
                try
                {
                    var doc = JsonDocument.Parse(request.Body);
                    if (doc.RootElement.TryGetProperty("grant_type", out var grantTypeElement))
                    {
                        return grantTypeElement.GetString() ?? "";
                    }
                }
                catch
                {
                    // Ignore JSON parsing errors
                }
            }

            // Default to client_credentials if not specified
            return "client_credentials";
        }        private Task<IHttpResponse> HandleDiscoveryRequest(IHttpRequest request)
        {
            // Try to extract the base URL from the request URL
            // Example: https://test-auth.example.com/.well-known/oauth-authorization-server
            var url = request.Url;
            var baseUrl = url;
            var idx = url.IndexOf("/.well-known/");
            if (idx > 0)
                baseUrl = url.Substring(0, idx);

            var discovery = new
            {
                issuer = baseUrl,
                authorization_endpoint = baseUrl + "/authorize",
                token_endpoint = baseUrl + "/token",
                jwks_uri = baseUrl + "/jwks",
                introspection_endpoint = baseUrl + "/introspect",
                revocation_endpoint = baseUrl + "/revoke",
                grant_types_supported = new[] { "client_credentials", "authorization_code", "refresh_token" },
                token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post", "tls_client_auth" }
            };

            var json = JsonSerializer.Serialize(discovery, new JsonSerializerOptions { WriteIndented = true });
            return Task.FromResult(CreateResponse(200, json, "application/json"));
        }

        private Task<IHttpResponse> HandleJwksRequest(IHttpRequest request)
        {
            var jwks = new
            {
                keys = new[]
                {
                    new
                    {
                        kty = "RSA",
                        use = "sig",
                        kid = "mock-key-1",
                        n = "mock-modulus-value",
                        e = "AQAB"
                    }
                }
            };

            var json = JsonSerializer.Serialize(jwks, new JsonSerializerOptions { WriteIndented = true });
            return Task.FromResult(CreateResponse(200, json, "application/json"));
        }        private Task<IHttpResponse> HandleIntrospectionRequest(IHttpRequest request)
        {
            // Extract token from request body
            string? token = ExtractTokenFromBody(request.Body);

            _logger?.LogDebug("[INTROSPECTION DEBUG] Received token: {Token}", token);

            // Check if token is revoked
            if (!string.IsNullOrEmpty(token) && _revokedTokens.Contains(token))
            {
                _logger?.LogDebug("[INTROSPECTION DEBUG] Token is revoked: {Token}", token);
                var revokedResponse = new { active = false };
                return Task.FromResult(CreateResponse(200, JsonSerializer.Serialize(revokedResponse), "application/json"));
            }

            // For introspection, we should be more permissive - if we have a token, it's likely valid
            // unless it's specifically revoked or empty/null
            bool isValid = !string.IsNullOrEmpty(token) && IsValidJwt(token);

            _logger?.LogDebug("[INTROSPECTION DEBUG] Token validation result: {IsValid} for token: {Token}", isValid, token);

            var response = new
            {
                active = isValid,
                sub = "user123",
                client_id = "test-client",
                scope = "read write",
                exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
                iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                username = "testuser"
            };

            var json = JsonSerializer.Serialize(response);
            _logger?.LogDebug("[INTROSPECTION DEBUG] Returning response: {Response}", json);
            return Task.FromResult(CreateResponse(200, json, "application/json"));
        }

        private Task<IHttpResponse> HandleRevocationRequest(IHttpRequest request)
        {
            // Extract token from request body
            string? token = ExtractTokenFromBody(request.Body);

            if (!string.IsNullOrEmpty(token))
            {
                _revokedTokens.Add(token);
                _logger?.LogDebug("Token revoked: {Token}", token);
            }

            // OAuth2 revocation endpoint should return 200 OK even for invalid tokens
            return Task.FromResult(CreateResponse(200, "", "application/json"));
        }

        private string? ExtractTokenFromBody(string? body)
        {
            if (string.IsNullOrEmpty(body))
                return null;

            // Handle form-encoded data
            var pairs = body.Split('&');
            foreach (var pair in pairs)
            {
                var parts = pair.Split('=');
                if (parts.Length == 2 && parts[0] == "token")
                {
                    return System.Web.HttpUtility.UrlDecode(parts[1]);
                }
            }

            return null;
        }

        private IHttpResponse CreateClientCredentialsResponse()
        {
            var response = new
            {
                access_token = "mock-access-token-client-credentials",
                token_type = "Bearer",
                expires_in = 3600,
                scope = "read write"
            };

            return CreateResponse(200, JsonSerializer.Serialize(response), "application/json");
        }

        private IHttpResponse CreatePasswordGrantResponse()
        {
            var response = new
            {
                access_token = "mock-access-token-password",
                token_type = "Bearer",
                expires_in = 3600,
                refresh_token = "mock-refresh-token",
                scope = "read write"
            };

            return CreateResponse(200, JsonSerializer.Serialize(response), "application/json");
        }

        private IHttpResponse CreateRefreshTokenResponse()
        {
            var response = new
            {
                access_token = "mock-access-token-refreshed",
                token_type = "Bearer",
                expires_in = 3600,
                refresh_token = "mock-refresh-token-new",
                scope = "read write"
            };

            return CreateResponse(200, JsonSerializer.Serialize(response), "application/json");
        }

        private IHttpResponse CreateAuthorizationCodeResponse()
        {
            var response = new
            {
                access_token = "auth-code-token",
                token_type = "Bearer",
                expires_in = 3600,
                refresh_token = "auth-code-refresh-token",
                scope = "read write"
            };

            return CreateResponse(200, JsonSerializer.Serialize(response), "application/json");
        }

        private IHttpResponse CreateErrorResponse(string error, string description)
        {
            var response = new
            {
                error = error,
                error_description = description
            };

            return CreateResponse(400, JsonSerializer.Serialize(response), "application/json");
        }
        private IHttpResponse CreateResponse(int statusCode, string body, string contentType)
        {
            var headers = new Dictionary<string, string>
            {
                ["Content-Type"] = contentType,
                ["Content-Length"] = Encoding.UTF8.GetByteCount(body).ToString()
            };

            var response = new MockHttpResponse(statusCode, body, headers);
            return response;
        }
        public IHttpRequest CreateRequest()
        {
            return new MockHttpRequest();
        }

        private void SetupDefaultOAuth2Responses()
        {
            // Set up default token endpoint responses
            var defaultTokenResponse = new
            {
                access_token = "test-access-token",
                token_type = "Bearer",
                expires_in = 3600,
                scope = "read write"
            };

            var defaultTokenJson = JsonSerializer.Serialize(defaultTokenResponse);

            // Add some common OAuth2 endpoints
            _predefinedResponses["https://oauth.example.com/token"] = CreateResponse(200, defaultTokenJson, "application/json");
            _predefinedResponses["https://oauth.example.com/oauth2/token"] = CreateResponse(200, defaultTokenJson, "application/json");
        }

        /// <summary>
        /// Sanitize request body for logging to hide sensitive information like client secrets
        /// </summary>
        private string SanitizeRequestBody(string? body)
        {
            if (string.IsNullOrEmpty(body))
                return body ?? "";

            // Hide client_secret values in form-encoded data
            var sanitized = body;
            if (sanitized.Contains("client_secret="))
            {
                // Replace client_secret value with [REDACTED]
                sanitized = System.Text.RegularExpressions.Regex.Replace(
                    sanitized,
                    @"client_secret=[^&]*",
                    "client_secret=[REDACTED]");
            }

            return sanitized;
        }

        /// <summary>
        /// Check if a request is rate limited based on URL and timing
        /// </summary>
        private bool IsRateLimited(string url)
        {
            var now = DateTime.UtcNow;
            var oneSecondAgo = now.AddSeconds(-1);

            // Initialize request count list for this URL if not exists
            if (!_requestCounts.ContainsKey(url))
                _requestCounts[url] = new List<DateTime>();

            var requestTimes = _requestCounts[url];

            // Remove requests older than 1 second
            requestTimes.RemoveAll(time => time < oneSecondAgo);

            // Add current request time
            requestTimes.Add(now);

            // Check if we've exceeded the rate limit
            return requestTimes.Count > RateLimitThreshold;
        }        /// <summary>
        /// Validate JWT token structure and check for tampering
        /// </summary>
        private bool IsValidJwt(string token)
        {
            try
            {
                // Split JWT into parts
                var parts = token.Split('.');
                if (parts.Length != 3)
                {
                    // For non-JWT tokens, check against valid mock tokens
                    var validTokens = new[]
                    {
                        "mock-access-token-client-credentials",
                        "mock-access-token-refreshed",
                        "auth-code-token",
                        "test-access-token",
                        "test-access-token-static",
                        "jwt-access-token",
                        "concurrent-token",
                        "new-access-token"
                    };

                    // Check exact matches first
                    if (validTokens.Any(vt => token.Equals(vt)))
                        return true;

                    // Check for pattern matches (e.g., tokens generated by MockAuthClient)
                    if (token.StartsWith("mock_access_token_") || 
                        token.StartsWith("mock-access-token-client-credent") ||
                        token.StartsWith("mock-access-token") ||
                        token.StartsWith("test-access-token"))
                        return true;

                    return false;
                }

                // For actual JWT tokens, try to decode and check structure
                try
                {
                    var payload = parts[1];
                    // Add padding if needed for base64 decoding
                    switch (payload.Length % 4)
                    {
                        case 2: payload += "=="; break;
                        case 3: payload += "="; break;
                    }

                    var bytes = Convert.FromBase64String(payload);
                    var json = Encoding.UTF8.GetString(bytes);

                    // If it contains "tampered" claim, it's invalid
                    if (json.Contains("\"tampered\""))
                        return false;

                    // Parse the JWT payload to check expiration
                    var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("exp", out var expElement))
                    {
                        if (expElement.TryGetInt64(out var exp))
                        {
                            var expDateTime = DateTimeOffset.FromUnixTimeSeconds(exp);
                            var now = DateTimeOffset.UtcNow;
                            
                            // Token is invalid if it's expired
                            if (expDateTime <= now)
                            {
                                return false;
                            }
                        }
                    }

                    return true;
                }
                catch
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }        }

        /// <summary>
        /// Check if request contains invalid credentials
        /// </summary>
        private bool HasInvalidCredentials(string? body)
        {
            if (string.IsNullOrEmpty(body))
                return false;

            return body.Contains("client_id=invalid-client") ||
                   body.Contains("client_id=invalid-client-id") ||
                   body.Contains("client_secret=invalid-secret") ||
                   body.Contains("client_secret=invalid-client-secret");
        }

        /// <summary>
        /// Set up a successful token response for the specified token URL
        /// </summary>
        public void SetSuccessfulTokenResponse(string tokenUrl, string accessToken, string tokenType, int expiresIn, string? refreshToken, string scope)
        {
            var response = new
            {
                access_token = accessToken,
                token_type = tokenType,
                expires_in = expiresIn,
                refresh_token = refreshToken,
                scope = scope
            };

            var json = JsonSerializer.Serialize(response, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
            });

            var headers = new Dictionary<string, string>
            {
                ["Content-Type"] = "application/json"
            };

            var mockResponse = new MockHttpResponse(200, json, headers);
            _predefinedResponses[tokenUrl] = mockResponse;
        }

        /// <summary>
        /// Set up an error token response for the specified token URL
        /// </summary>
        public void SetErrorTokenResponse(string tokenUrl, string error, string errorDescription, int statusCode)
        {
            var response = new
            {
                error = error,
                error_description = errorDescription
            };

            var json = JsonSerializer.Serialize(response, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
            });

            var headers = new Dictionary<string, string>
            {
                ["Content-Type"] = "application/json"
            };            var mockResponse = new MockHttpResponse(statusCode, json, headers);
            _predefinedResponses[tokenUrl] = mockResponse;
        }

        /// <summary>
        /// Redact sensitive data from request bodies for safe logging
        /// </summary>
        private static string RedactSensitiveData(string requestBody)
        {
            if (string.IsNullOrEmpty(requestBody))
                return requestBody;

            // Redact client_secret parameters
            var redacted = System.Text.RegularExpressions.Regex.Replace(
                requestBody, 
                @"client_secret=[^&]*", 
                "client_secret=[REDACTED]",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            // Redact password parameters
            redacted = System.Text.RegularExpressions.Regex.Replace(
                redacted, 
                @"password=[^&]*", 
                "password=[REDACTED]",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            return redacted;
        }
    }
}