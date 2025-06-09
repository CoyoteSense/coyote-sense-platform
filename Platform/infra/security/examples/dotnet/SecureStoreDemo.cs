using System;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Auth.Examples;
using Coyote.Infra.Security.Auth.Extensions;
using Coyote.Infra.Security.Auth.Options;

namespace Coyote.Infra.Security.Tests.Examples;

/// <summary>
/// Console application demonstrating the SecureStoreClient implementation
/// Shows both standalone usage and dependency injection integration
/// </summary>
class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("🔐 CoyoteSense SecureStoreClient Demo");
        Console.WriteLine("====================================");

        if (args.Length > 0 && args[0] == "--di")
        {
            await RunDependencyInjectionExample();
        }
        else
        {
            await RunStandaloneExamples();
        }

        Console.WriteLine("\n👋 Demo completed!");
    }

    /// <summary>
    /// Run examples using standalone client instances
    /// </summary>
    static async Task RunStandaloneExamples()
    {
        Console.WriteLine("Running standalone examples...\n");

        try
        {
            // Run the integrated auth client examples
            Console.WriteLine("=== IAuthClient Examples ===");
            await AuthClientExamples.RunAllExamples();

            Console.WriteLine("\n=== ISecureStoreClient Examples ===");
            await SecureStoreClientExamples.RunAllExamples();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Standalone examples failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Run examples using dependency injection
    /// </summary>
    static async Task RunDependencyInjectionExample()
    {
        Console.WriteLine("Running dependency injection example...\n");

        try
        {
            // Build host with DI container
            var host = Host.CreateDefaultBuilder()
                .ConfigureServices((context, services) =>
                {
                    // Configure logging
                    services.AddLogging(builder => builder.AddConsole());

                    // Add SecureStoreClient with integrated auth
                    services.AddSecureStoreClientWithAuth(options =>
                    {
                        options.ServerUrl = "https://keyvault.coyotesense.io";
                        options.UseIntegratedAuth = true;
                        options.RequiredScopes = new[] { "keyvault.read", "keyvault.write" }.ToList();
                        options.AuthClientConfig = new AuthClientConfig
                        {
                            AuthMode = AuthMode.ClientCredentials,
                            ServerUrl = "https://auth.coyotesense.io",
                            ClientId = "demo-client",
                            ClientSecret = Environment.GetEnvironmentVariable("CLIENT_SECRET") ?? "demo-secret",
                            DefaultScopes = new[] { "keyvault.read", "keyvault.write" }.ToList()
                        };
                    });

                    // Add health checks
                    services.AddHealthChecks();

                    // Add background service for monitoring
                    services.AddHostedService<SecureStoreBackgroundService>();

                    // Add demo service
                    services.AddScoped<DemoService>();
                })
                .Build();

            // Run the demo
            using (host)
            {
                await host.StartAsync();

                var demoService = host.Services.GetRequiredService<DemoService>();
                await demoService.RunDemoAsync();

                await host.StopAsync();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Dependency injection example failed: {ex.Message}");
        }
    }
}

/// <summary>
/// Demo service showing SecureStoreClient usage in a real application
/// </summary>
public class DemoService
{
    private readonly ISecureStoreClient _secureStoreClient;
    private readonly ILogger<DemoService> _logger;

    public DemoService(ISecureStoreClient secureStoreClient, ILogger<DemoService> logger)
    {
        _secureStoreClient = secureStoreClient;
        _logger = logger;
    }

    public async Task RunDemoAsync()
    {
        _logger.LogInformation("🚀 Starting SecureStoreClient demo service");

        try
        {
            // Test connection
            var isConnected = await _secureStoreClient.TestConnectionAsync();
            if (isConnected)
            {
                _logger.LogInformation("✅ SecureStore connection successful");
            }
            else
            {
                _logger.LogWarning("❌ SecureStore connection failed");
                return;
            }

            // Get health status
            var health = await _secureStoreClient.GetHealthStatusAsync();
            if (health != null)
            {
                _logger.LogInformation("🏥 KeyVault health: {Status} - {IsHealthy}", health.Status, health.IsHealthy);
            }

            // Simulate application startup - load configuration secrets
            await LoadApplicationSecretsAsync();

            // Simulate runtime operations
            await SimulateRuntimeOperationsAsync();

            _logger.LogInformation("✅ Demo service completed successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Demo service failed");
        }
    }

    private async Task LoadApplicationSecretsAsync()
    {
        _logger.LogInformation("🔄 Loading application configuration secrets...");

        try
        {
            var configSecrets = new[]
            {
                "app/database/connection_string",
                "app/external_apis/stripe_key",
                "app/external_apis/sendgrid_key",
                "app/certificates/jwt_signing_key"
            };

            var secrets = await _secureStoreClient.GetSecretsAsync(configSecrets);
            
            _logger.LogInformation("📦 Loaded {Count} configuration secrets", secrets.Count);

            // Simulate using the secrets for configuration
            foreach (var secret in secrets)
            {
                _logger.LogInformation("⚙️ Configuring: {SecretKey}", secret.Key.Split('/').Last());
                
                // In a real app, you'd use these to configure services
                // e.g., database connections, external API clients, etc.
                
                // Secure cleanup
                secret.Value.Clear();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load application secrets");
        }
    }

    private async Task SimulateRuntimeOperationsAsync()
    {
        _logger.LogInformation("🔄 Simulating runtime secret operations...");

        try
        {
            // Simulate storing a new runtime secret
            var runtimeSecret = $"runtime-generated-{DateTime.UtcNow:yyyyMMdd-HHmmss}";
            var metadata = new Dictionary<string, string>
            {
                ["generated_at"] = DateTime.UtcNow.ToString("O"),
                ["purpose"] = "demo_runtime_operation",
                ["ttl"] = "3600" // 1 hour
            };

            var version = await _secureStoreClient.SetSecretAsync(
                "app/runtime/demo_secret", 
                runtimeSecret, 
                metadata);

            _logger.LogInformation("💾 Stored runtime secret (version: {Version})", version);

            // Retrieve it back
            var retrievedSecret = await _secureStoreClient.GetSecretAsync("app/runtime/demo_secret");
            if (retrievedSecret != null)
            {
                _logger.LogInformation("🔑 Retrieved runtime secret (version: {Version})", retrievedSecret.Version);
                retrievedSecret.Clear();
            }

            // List secrets in runtime namespace
            var runtimeSecrets = await _secureStoreClient.ListSecretsAsync("app/runtime/");
            _logger.LogInformation("📁 Found {Count} runtime secrets", runtimeSecrets.Count);

            // Clean up the demo secret
            var deleted = await _secureStoreClient.DeleteSecretAsync("app/runtime/demo_secret");
            if (deleted)
            {
                _logger.LogInformation("🗑️ Cleaned up demo secret");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed runtime operations");
        }
    }
}

/// <summary>
/// Configuration class for the demo
/// </summary>
public class DemoConfiguration
{
    public string KeyVaultUrl { get; set; } = "https://keyvault.coyotesense.io";
    public string AuthServerUrl { get; set; } = "https://auth.coyotesense.io";
    public string ClientId { get; set; } = "demo-client";
    public string? ClientSecret { get; set; }
    public bool EnableMockMode { get; set; } = true; // For demo purposes
}
