using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Factory;

namespace Coyote.Infra.Http.Examples;

/// <summary>
/// Example demonstrating how to use the Coyote HTTP client infrastructure
/// </summary>
public class HttpClientExample
{
    /// <summary>
    /// Basic usage example with dependency injection
    /// </summary>
    public static async Task BasicUsageExample()
    {
        // Setup DI container
        var services = new ServiceCollection();
        
        // Add logging
        services.AddLogging(builder => builder.AddConsole());
        
        // Add configuration
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Coyote:Http:DefaultTimeoutMs"] = "30000",
                ["Coyote:Http:UserAgent"] = "Coyote-Example/1.0",
                ["Coyote:Http:Mode:Mode"] = "Testing"
            })
            .Build();
        
        // Register HTTP client infrastructure
        services.AddCoyoteHttpClient(configuration);
        
        // Build service provider
        var serviceProvider = services.BuildServiceProvider();
        
        // Get HTTP client (will be mock client due to Testing mode)
        var httpClient = serviceProvider.GetRequiredService<ICoyoteHttpClient>();
        
        // Use the client
        var response = await httpClient.GetAsync("https://api.example.com/data");
        
        Console.WriteLine($"Status: {response.StatusCode}");
        Console.WriteLine($"Body: {response.Body}");
        Console.WriteLine($"Success: {response.IsSuccess}");
    }

    /// <summary>
    /// Example with explicit mode configuration
    /// </summary>
    public static async Task ExplicitModeExample()
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole());
        
        // Configure with explicit mode settings
        services.AddCoyoteHttpClient(
            configureHttp: options =>
            {
                options.DefaultTimeoutMs = 15000;
                options.UserAgent = "Coyote-ExplicitMode/1.0";
                options.DefaultHeaders["X-API-Key"] = "your-api-key";
            },
            configureMode: options =>
            {
                options.Mode = RuntimeMode.Testing;
                options.Mock.DefaultStatusCode = 200;
                options.Mock.DefaultBody = "{\"message\": \"Hello from mock\"}";
            });
        
        var serviceProvider = services.BuildServiceProvider();
        var httpClient = serviceProvider.GetRequiredService<ICoyoteHttpClient>();
        
        // Use the client
        var response = await httpClient.PostJsonAsync("https://api.example.com/create", 
            new { Name = "Test", Value = 42 });
        
        Console.WriteLine($"Response: {response.Body}");
    }

    /// <summary>
    /// Example showing factory usage for different modes
    /// </summary>
    public static async Task FactoryModeExample()
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole());
        services.AddCoyoteHttpClient();
        
        var serviceProvider = services.BuildServiceProvider();
        var factory = serviceProvider.GetRequiredService<IHttpClientFactory>();
        
        // Create clients for different modes
        var testingClient = factory.CreateHttpClientForMode(RuntimeMode.Testing);
        var productionClient = factory.CreateHttpClientForMode(RuntimeMode.Production);
        var debugClient = factory.CreateHttpClientForMode(RuntimeMode.Debug);
        
        Console.WriteLine($"Testing client type: {testingClient.GetType().Name}");
        Console.WriteLine($"Production client type: {productionClient.GetType().Name}");
        Console.WriteLine($"Debug client type: {debugClient.GetType().Name}");
        
        // Test each client
        var url = "https://httpbin.org/get";
        
        var testResponse = await testingClient.GetAsync(url);
        Console.WriteLine($"Test response status: {testResponse.StatusCode}");
        
        // Note: Production client would make real HTTP calls
        // var prodResponse = await productionClient.GetAsync(url);
        // Console.WriteLine($"Production response status: {prodResponse.StatusCode}");
        
        testingClient.Dispose();
        productionClient.Dispose();
        debugClient.Dispose();
    }

    /// <summary>
    /// Example showing mock client configuration
    /// </summary>
    public static async Task MockClientConfigurationExample()
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole());
        services.AddCoyoteHttpClient(configureMode: options => options.Mode = RuntimeMode.Testing);
        
        var serviceProvider = services.BuildServiceProvider();
        var factory = serviceProvider.GetRequiredService<IHttpClientFactory>();
        var mockClient = factory.CreateHttpClientForMode(RuntimeMode.Testing) as MockHttpClient;
        
        if (mockClient != null)
        {
            // Configure custom responses
            mockClient.SetPredefinedJsonResponse("https://api.example.com/users", 
                new[] { 
                    new { Id = 1, Name = "John" }, 
                    new { Id = 2, Name = "Jane" } 
                });
            
            mockClient.SetPredefinedResponse("https://api.example.com/error", 
                500, "{\"error\": \"Internal server error\"}", 
                new Dictionary<string, string> { ["Content-Type"] = "application/json" });
            
            // Test the configured responses
            var usersResponse = await mockClient.GetAsync("https://api.example.com/users");
            Console.WriteLine($"Users response: {usersResponse.Body}");
            
            var errorResponse = await mockClient.GetAsync("https://api.example.com/error");
            Console.WriteLine($"Error response status: {errorResponse.StatusCode}");
            Console.WriteLine($"Error response: {errorResponse.Body}");
            
            mockClient.Dispose();
        }
    }

    /// <summary>
    /// Example using Host and configuration files
    /// </summary>
    public static async Task HostBuilderExample()
    {
        var host = Host.CreateDefaultBuilder()
            .ConfigureServices((context, services) =>
            {
                // Register HTTP client with configuration from appsettings.json
                services.AddCoyoteHttpClient(context.Configuration);
                
                // Register application services
                services.AddScoped<ApiService>();
            })
            .Build();
        
        var apiService = host.Services.GetRequiredService<ApiService>();
        
        await apiService.CallExternalApiAsync();
        
        await host.StopAsync();
    }
}

/// <summary>
/// Example service that uses the HTTP client
/// </summary>
public class ApiService
{
    private readonly ICoyoteHttpClient _httpClient;
    private readonly ILogger<ApiService> _logger;

    public ApiService(ICoyoteHttpClient httpClient, ILogger<ApiService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<string> CallExternalApiAsync()
    {
        try
        {
            _logger.LogInformation("Calling external API");
            
            var response = await _httpClient.GetAsync("https://api.example.com/data");
            
            if (response.IsSuccess)
            {
                _logger.LogInformation("API call successful");
                return response.Body;
            }
            else
            {
                _logger.LogWarning("API call failed with status {StatusCode}", response.StatusCode);
                return string.Empty;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calling external API");
            throw;
        }
    }
    
    public async Task<T?> PostDataAsync<T>(string endpoint, object data)
    {
        var response = await _httpClient.PostJsonAsync(endpoint, data);
        
        if (response.IsSuccess)
        {
            return response.GetContent<T>();
        }
        
        return default;
    }
}
