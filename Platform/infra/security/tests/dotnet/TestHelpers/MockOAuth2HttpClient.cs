using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Http;

namespace Coyote.Infra.Security.Tests.TestHelpers
{    /// <summary>
    /// Mock HTTP client for OAuth2 authentication testing
    /// Implements ICoyoteHttpClient interface with pre-configured responses for OAuth2 endpoints
    /// </summary>
    public class MockOAuth2HttpClient : ICoyoteHttpClient
    {
        #region Private Fields

        private readonly ILogger<MockOAuth2HttpClient>? _logger;
        private readonly Dictionary<string, IHttpResponse> _predefinedResponses = new();
        private readonly List<IHttpRequest> _recordedRequests = new();
        private readonly HashSet<string> _revokedTokens = new();
        private readonly Dictionary<string, Exception> _exceptionMap = new();
        private bool _recordRequests = true;
        private bool _disposed;

        #endregion

        #region Constructor

        /// <summary>
        /// Create a new MockOAuth2HttpClient with optional logging
        /// </summary>
        public MockOAuth2HttpClient(ILogger<MockOAuth2HttpClient>? logger = null)
        {
            _logger = logger;
            
            // Set up default successful OAuth2 token response
            SetupDefaultOAuth2Responses();
        }

        #endregion        
          #region ICoyoteHttpClient Interface Methods        
        
        /// <summary>
        /// Execute a request (main method that all other methods call)
        /// </summary>
        public Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));

            // Log all incoming requests at INFO level to ensure they're visible
            Console.WriteLine($"[MockHttpClient] ExecuteAsync called: {request.Method} {request.Url}");
            _logger?.LogInformation("MockHttpClient ExecuteAsync: {Method} {Url}", request.Method, request.Url);

            // Check if an exception should be thrown for this URL
            if (_exceptionMap.TryGetValue(request.Url, out var exception))
            {
                Console.WriteLine($"[MockHttpClient] Throwing configured exception for URL: {request.Url}");
                _logger?.LogDebug("Throwing configured exception for URL: {Url}", request.Url);
                throw exception;
            }

            // Record the request if enabled
            if (_recordRequests)
            {
                _recordedRequests.Add(request);
                _logger?.LogDebug("Recorded request: {Method} {Url}", request.Method, request.Url);
            }

            // Look for predefined response matching this URL exactly
            if (_predefinedResponses.TryGetValue(request.Url, out var exactResponse))
            {
                Console.WriteLine($"[MockHttpClient] Found exact match for URL: {request.Url}");
                _logger?.LogDebug("Found exact match for URL: {Url}", request.Url);
                return Task.FromResult(exactResponse);
            }

            // Debug: Print all predefined response URLs for troubleshooting
            Console.WriteLine($"[MockHttpClient] Checking predefined responses. Total count: {_predefinedResponses.Count}");
            foreach (var kvp in _predefinedResponses)
            {
                Console.WriteLine($"[MockHttpClient] Predefined URL: {kvp.Key}");
            }

            // Try pattern matching for token endpoints
            if (request.Url.Contains("/oauth2/token") || 
                request.Url.Contains("/oauth/token") ||
                request.Url.Contains("/connect/token") ||
                request.Url.EndsWith("/token"))
            {
                Console.WriteLine($"[MockHttpClient] OAuth2 token endpoint detected: {request.Url}");
                _logger?.LogDebug("OAuth2 token endpoint detected: {Url}", request.Url);
                
                // Check if there's a predefined response for this exact token URL first
                if (_predefinedResponses.ContainsKey(request.Url))
                {
                    Console.WriteLine($"[MockHttpClient] Using predefined response for token URL: {request.Url}");
                    _logger?.LogDebug("Using predefined response for token URL: {Url}", request.Url);
                    return Task.FromResult(_predefinedResponses[request.Url]);
                }
                
                return HandleTokenRequest(request);
            }

            // Try pattern matching for introspection endpoints
            if (request.Url.Contains("/introspect"))
            {
                Console.WriteLine($"[MockHttpClient] OAuth2 introspection endpoint detected: {request.Url}");
                _logger?.LogDebug("OAuth2 introspection endpoint detected: {Url}", request.Url);
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
        }        public Task<IHttpResponse> PostAsync(string url, string? body = null, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
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
        }        public Task<IHttpResponse> PostJsonAsync<T>(string url, T content, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
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
        }        public Task<IHttpResponse> PutAsync(string url, string? body = null, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
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
        }        public Task<IHttpResponse> PutJsonAsync<T>(string url, T content, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
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
        }        public Task<IHttpResponse> DeleteAsync(string url, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
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
        }        public Task<IHttpResponse> PatchAsync(string url, string? body = null, IReadOnlyDictionary<string, string>? headers = null, CancellationToken cancellationToken = default)
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

        public Task<bool> PingAsync(string url, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true); // Always succeed for mock
        }

        public IHttpRequest CreateRequest()
        {
            return new HttpRequest();
        }

        #endregion

        #region Mock Configuration Methods

        /// <summary>
        /// Set a predefined response for a specific URL
        /// </summary>
        public void SetPredefinedResponse(string url, int statusCode, string body, IDictionary<string, string>? headers = null)
        {
            var response = CreateResponse(statusCode, body, headers: headers);
            _predefinedResponses[url] = response;
            _logger?.LogDebug("Set predefined response for URL: {Url}, Status: {Status}", url, statusCode);
        }

        /// <summary>
        /// Set a predefined JSON response for a specific URL
        /// </summary>
        public void SetPredefinedJsonResponse<T>(string url, T content, int statusCode = 200)
        {
            var jsonBody = JsonSerializer.Serialize(content);
            var headers = new Dictionary<string, string>
            {
                ["Content-Type"] = "application/json"
            };
            SetPredefinedResponse(url, statusCode, jsonBody, headers);
        }

        /// <summary>
        /// Enable or disable request recording
        /// </summary>
        public void SetRecordRequests(bool record)
        {
            _recordRequests = record;
        }

        /// <summary>
        /// Get all recorded requests
        /// </summary>
        public IReadOnlyList<IHttpRequest> GetRecordedRequests()
        {
            return _recordedRequests;
        }

        /// <summary>
        /// Clear all recorded requests
        /// </summary>
        public void ClearRecordedRequests()
        {
            _recordedRequests.Clear();
        }

        /// <summary>
        /// Set up a valid access token response
        /// </summary>
        public void SetSuccessfulTokenResponse(string url, string accessToken = "mock-access-token", 
            string tokenType = "Bearer", int expiresIn = 3600, string? refreshToken = null, 
            string scope = "read write")
        {
            var response = new
            {
                access_token = accessToken,
                token_type = tokenType,
                expires_in = expiresIn,
                refresh_token = refreshToken,
                scope = scope
            };
            
            SetPredefinedJsonResponse(url, response);
        }

        /// <summary>
        /// Set up an error token response
        /// </summary>
        public void SetErrorTokenResponse(string url, string error = "invalid_client", 
            string errorDescription = "Invalid client credentials", int statusCode = 400)
        {
            var response = new
            {
                error = error,
                error_description = errorDescription
            };
            
            SetPredefinedJsonResponse(url, response, statusCode);
        }

        /// <summary>
        /// Configure an exception to be thrown for a specific URL
        /// </summary>
        public void SetExceptionForUrl(string url, Exception exception)
        {
            _exceptionMap[url] = exception;
            _logger?.LogDebug("Set exception for URL: {Url}, Exception: {Exception}", url, exception.GetType().Name);
        }

        /// <summary>
        /// Clear all configured exceptions
        /// </summary>
        public void ClearExceptions()
        {
            _exceptionMap.Clear();
        }

        #endregion

        #region Helper Methods
        
        private Task<IHttpResponse> HandleTokenRequest(IHttpRequest request)
        {
            // Parse form data or check JSON body to determine grant type
            string grantType = GetGrantTypeFromRequest(request);
            
            _logger?.LogDebug("Handling token request with grant type: {GrantType}", grantType);
            _logger?.LogDebug("Request URL: {Url}", request.Url);
            _logger?.LogDebug("Request Body: {Body}", request.Body);
            
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
            {                // Check if it's form URL encoded
                if (request.Headers.TryGetValue("Content-Type", out var contentType) && contentType.Contains("application/x-www-form-urlencoded"))
                {
                    var formData = ParseFormData(request.Body);
                    if (formData.TryGetValue("grant_type", out var grantType))
                    {
                        return grantType;
                    }
                }
                
                // Check if it's JSON
                else if (request.Headers.TryGetValue("Content-Type", out var jsonContentType) && jsonContentType.Contains("application/json"))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(request.Body);
                        if (doc.RootElement.TryGetProperty("grant_type", out var grantTypeElement))
                        {
                            return grantTypeElement.GetString() ?? "client_credentials";
                        }
                    }
                    catch
                    {
                        // JSON parsing failed, ignore
                    }
                }
            }
            
            // Default to client credentials if we can't determine
            return "client_credentials";
        }

        private Dictionary<string, string> ParseFormData(string formData)
        {
            var result = new Dictionary<string, string>();
            
            if (string.IsNullOrEmpty(formData))
                return result;
                
            var pairs = formData.Split('&');
            foreach (var pair in pairs)
            {
                var keyValue = pair.Split('=');
                if (keyValue.Length == 2)
                {
                    result[Uri.UnescapeDataString(keyValue[0])] = Uri.UnescapeDataString(keyValue[1]);
                }
            }
            
            return result;
        }        private void SetupDefaultOAuth2Responses()
        {
            // Do not set predefined responses for token endpoints to allow dynamic handling
            // based on grant type in request body. The HandleTokenRequest method will handle
            // all token requests dynamically.
            
            // We can still set up other non-token endpoints if needed
            // For example: discovery endpoints, JWKS endpoints, etc.
        }private IHttpResponse CreateResponse(int statusCode, string body, string contentType = "text/plain", IDictionary<string, string>? headers = null)
        {
            var responseHeaders = new Dictionary<string, string>
            {
                ["Content-Type"] = contentType
            };
            
            if (headers != null)
            {
                foreach (var header in headers)
                {
                    responseHeaders[header.Key] = header.Value;
                }
            }
            
            return new HttpResponse
            {
                StatusCode = statusCode,
                Body = body,
                Headers = responseHeaders,
                ErrorMessage = statusCode >= 400 ? "Error response" : null
            };
        }        private IHttpResponse CreateClientCredentialsResponse()
        {
            var responseObj = new
            {
                access_token = "mock-access-token-client-credentials",
                token_type = "Bearer",
                expires_in = 3600,
                refresh_token = "mock-refresh-token-client-credentials",
                scope = "read write"
            };
            
            var json = JsonSerializer.Serialize(responseObj);
            return CreateResponse(200, json, "application/json");
        }

        private IHttpResponse CreatePasswordGrantResponse()
        {
            var responseObj = new
            {
                access_token = "mock-access-token-password",
                token_type = "Bearer",
                expires_in = 3600,
                refresh_token = "mock-refresh-token-password",
                scope = "read write"
            };
            
            var json = JsonSerializer.Serialize(responseObj);
            return CreateResponse(200, json, "application/json");
        }

        private IHttpResponse CreateRefreshTokenResponse()
        {
            var responseObj = new
            {
                access_token = "mock-access-token-refreshed",
                token_type = "Bearer",
                expires_in = 3600,
                refresh_token = "mock-refresh-token-new",
                scope = "read write"
            };
            
            var json = JsonSerializer.Serialize(responseObj);
            return CreateResponse(200, json, "application/json");
        }        private IHttpResponse CreateAuthorizationCodeResponse()
        {
            var responseObj = new
            {
                access_token = "mock-access-token-auth-code",
                token_type = "Bearer",
                expires_in = 3600,
                refresh_token = "mock-refresh-token-auth-code",
                id_token = "mock-id-token",
                scope = "read write openid profile"
            };
            
            var json = JsonSerializer.Serialize(responseObj);
            return CreateResponse(200, json, "application/json");
        }        private Task<IHttpResponse> HandleIntrospectionRequest(IHttpRequest request)
        {
            _logger?.LogDebug("Handling introspection request");
            
            // Extract token from form data
            string? token = null;
            if (!string.IsNullOrEmpty(request.Body))
            {
                if (request.Headers.TryGetValue("Content-Type", out var contentType) && contentType.Contains("application/x-www-form-urlencoded"))
                {
                    var formData = ParseFormData(request.Body);
                    formData.TryGetValue("token", out token);
                }
            }
            
            // Check if token was revoked
            bool isActive = !string.IsNullOrEmpty(token) && !_revokedTokens.Contains(token);
            
            var responseObj = new
            {
                active = isActive,
                scope = isActive ? "read write" : null,
                client_id = isActive ? "test-client-id" : null,
                token_type = isActive ? "Bearer" : null,
                exp = isActive ? DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds() : (long?)null,
                iat = isActive ? DateTimeOffset.UtcNow.ToUnixTimeSeconds() : (long?)null,
                sub = isActive ? "test-subject" : null
            };
            
            var json = JsonSerializer.Serialize(responseObj);
            return Task.FromResult(CreateResponse(200, json, "application/json"));
        }        private Task<IHttpResponse> HandleRevocationRequest(IHttpRequest request)
        {
            _logger?.LogDebug("Handling revocation request");
            
            // Extract token from form data
            if (!string.IsNullOrEmpty(request.Body))
            {
                if (request.Headers.TryGetValue("Content-Type", out var contentType) && contentType.Contains("application/x-www-form-urlencoded"))
                {
                    var formData = ParseFormData(request.Body);
                    if (formData.TryGetValue("token", out var token) && !string.IsNullOrEmpty(token))
                    {
                        _revokedTokens.Add(token);
                        _logger?.LogDebug("Token revoked: {Token}", token);
                    }
                }
            }
            
            // Per RFC 7009, token revocation should return 200 OK regardless of whether the token was valid
            return Task.FromResult(CreateResponse(200, "", "text/plain"));
        }

        private IHttpResponse CreateErrorResponse(string error, string errorDescription, int statusCode = 400)
        {
            var responseObj = new
            {
                error = error,
                error_description = errorDescription
            };
            
            var json = JsonSerializer.Serialize(responseObj);
            return CreateResponse(statusCode, json, "application/json");
        }

        #endregion

        #region IDisposable

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed resources
                    _predefinedResponses.Clear();
                    _recordedRequests.Clear();
                }

                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}