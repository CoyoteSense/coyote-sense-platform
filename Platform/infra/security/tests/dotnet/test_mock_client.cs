using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Modes.Mock;

namespace TestMockClient
{
    class Program
    {
        static async Task Main(string[] args)
        {
            try
            {
                Console.WriteLine("Testing Mock HTTP Client Implementation...");
                
                var options = new HttpClientOptions
                {
                    TimeoutMs = 30000,
                    UserAgent = "Test-Agent"
                };
                
                var testClient = new TestMockHttpClient(options);
                
                // Test 1: Mock token endpoint
                var tokenRequest = new HttpRequest
                {
                    Method = HttpMethod.Post,
                    Url = "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
                    Body = "grant_type=client_credentials",
                    Headers = new Dictionary<string, string> { ["Content-Type"] = "application/x-www-form-urlencoded" }
                };
                
                var tokenResponse = await testClient.ExecuteAsync(tokenRequest);
                Console.WriteLine($"Token Response: {tokenResponse.StatusCode} - {tokenResponse.Body}");
                
                // Test 2: Discovery endpoint
                var discoveryRequest = new HttpRequest
                {
                    Method = HttpMethod.Get,
                    Url = "https://login.microsoftonline.com/test-tenant/v2.0/.well-known/openid_configuration"
                };
                
                var discoveryResponse = await testClient.ExecuteAsync(discoveryRequest);
                Console.WriteLine($"Discovery Response: {discoveryResponse.StatusCode} - {discoveryResponse.Body}");
                
                // Test 3: Default endpoint (should use default mock response)
                var defaultRequest = new HttpRequest
                {
                    Method = HttpMethod.Get,
                    Url = "https://example.com/api/test"
                };
                
                var defaultResponse = await testClient.ExecuteAsync(defaultRequest);
                Console.WriteLine($"Default Response: {defaultResponse.StatusCode} - {defaultResponse.Body}");
                
                // Test 4: Ping test
                var pingResult = await testClient.PingAsync("https://example.com/health");
                Console.WriteLine($"Ping Result: {pingResult}");
                
                Console.WriteLine("Mock HTTP Client Implementation test completed successfully!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }
    }
    
    // Copy of the updated TestMockHttpClient for testing
    internal class TestMockHttpClient : BaseHttpClient
    {
        private readonly MockHttpClient _mockClient;
        
        public TestMockHttpClient(HttpClientOptions options) : base(options) 
        { 
            // Create mock options for OAuth2 testing
            var mockOptions = Microsoft.Extensions.Options.Options.Create(new HttpClientModeOptions
            {
                Mode = RuntimeMode.Testing,
                Mock = new MockResponseOptions
                {
                    DefaultStatusCode = 200,
                    DefaultBody = "{\"access_token\":\"mock_token\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
                    DefaultHeaders = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                    DelayMs = 10
                }
            });
            
            var httpOptions = Microsoft.Extensions.Options.Options.Create(options);
            
            // Create a simple logger for testing
            var loggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(builder => builder.AddConsole());
            var logger = loggerFactory.CreateLogger<MockHttpClient>();
            
            _mockClient = new MockHttpClient(httpOptions, mockOptions, logger);
            
            // Configure common OAuth2 endpoints with appropriate mock responses
            SetupOAuth2MockResponses();
        }
        
        private void SetupOAuth2MockResponses()
        {
            // Mock token endpoint response
            _mockClient.SetPredefinedJsonResponse("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token", 
                new { access_token = "mock_access_token", token_type = "Bearer", expires_in = 3600 });
                
            // Mock discovery endpoint response
            _mockClient.SetPredefinedJsonResponse("https://login.microsoftonline.com/test-tenant/v2.0/.well-known/openid_configuration",
                new { 
                    issuer = "https://login.microsoftonline.com/test-tenant/v2.0",
                    token_endpoint = "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
                    jwks_uri = "https://login.microsoftonline.com/test-tenant/discovery/v2.0/keys"
                });
        }
        
        public override async Task<IHttpResponse> ExecuteAsync(IHttpRequest request, CancellationToken cancellationToken = default)
        {
            return await _mockClient.ExecuteAsync(request, cancellationToken);
        }
        
        public override async Task<bool> PingAsync(string url, CancellationToken cancellationToken = default)
        {
            return await _mockClient.PingAsync(url, cancellationToken);
        }
    }
}
