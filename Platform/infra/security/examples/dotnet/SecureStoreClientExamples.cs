using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Auth.Clients;
using Coyote.Infra.Security.Auth.Options;
using Coyote.Infra.Security.Auth.Factory;

namespace Coyote.Infra.Security.Auth.Examples;

/// <summary>
/// Comprehensive examples demonstrating SecureStoreClient usage patterns
/// Shows various integration approaches and real-world scenarios
/// </summary>
public class SecureStoreClientExamples
{
    private const string KeyVaultUrl = "https://keyvault.coyotesense.io";
    private const string AuthServerUrl = "https://auth.coyotesense.io";
    private const string ClientId = "trading-service";

    /// <summary>
    /// Example: Basic secret retrieval with integrated authentication
    /// Most common pattern - everything configured together
    /// </summary>
    public static async Task BasicSecretRetrievalExample()
    {
        Console.WriteLine("\n=== Basic Secret Retrieval Example ===");

        // Create integrated configuration
        var authOptions = new SecureStoreAuthOptions
        {
            ServerUrl = KeyVaultUrl,
            UseIntegratedAuth = true,
            RequiredScopes = new List<string> { "keyvault.read", "keyvault.write" },
            AuthClientConfig = new AuthClientConfig
            {
                AuthMode = AuthMode.ClientCredentials,
                ServerUrl = AuthServerUrl,
                ClientId = ClientId,
                ClientSecret = Environment.GetEnvironmentVariable("CLIENT_SECRET") ?? "demo-secret",
                DefaultScopes = new List<string> { "keyvault.read", "keyvault.write" }
            }
        };

        using var client = SecureStoreClientFactory.CreateWithIntegratedAuth(authOptions);

        try
        {
            // Test connection first
            if (!await client.TestConnectionAsync())
            {
                Console.WriteLine("❌ Failed to connect to KeyVault");
                return;
            }

            // Retrieve database password
            var dbPassword = await client.GetSecretAsync("production/database/password");
            if (dbPassword != null)
            {
                Console.WriteLine($"✅ Retrieved database password (version: {dbPassword.Version})");
                Console.WriteLine($"   Created: {dbPassword.CreatedAt}");
                Console.WriteLine($"   Metadata: {string.Join(", ", dbPassword.Metadata)}");
                
                // Use the password securely
                await UsePasswordSecurely(dbPassword.Value);
                
                // Clear from memory
                dbPassword.Clear();
            }
            else
            {
                Console.WriteLine("❌ Database password not found");
            }
        }
        catch (SecureStoreException ex)
        {
            Console.WriteLine($"❌ SecureStore error: {ex.ErrorCode} - {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Unexpected error: {ex.Message}");
        }
    }

    /// <summary>
    /// Example: Multiple secrets retrieval for application configuration
    /// Efficient batch loading of related secrets
    /// </summary>
    public static async Task MultipleSecretsExample()
    {
        Console.WriteLine("\n=== Multiple Secrets Example ===");

        var options = new SecureStoreOptions
        {
            ServerUrl = KeyVaultUrl,
            DefaultNamespace = "production", // Automatically prefix all paths
            TimeoutMs = 15000
        };

        // Use external auth client (loose coupling)
        var authClient = AuthClientBuilder.CreateBuilder(AuthServerUrl, ClientId)
            .WithClientCredentialsFlow(Environment.GetEnvironmentVariable("CLIENT_SECRET") ?? "demo-secret")
            .WithDefaultScopes("keyvault.read")
            .Build();

        using var storeClient = SecureStoreClientFactory.CreateWithAuthClient(options, authClient);

        try
        {
            // Define all secrets we need for the application
            var secretPaths = new[]
            {
                "database/host",
                "database/password",
                "redis/connection_string",
                "external_api/stripe_key",
                "external_api/sendgrid_key",
                "certificates/jwt_signing_key"
            };

            Console.WriteLine("🔄 Retrieving application secrets...");
            var secrets = await storeClient.GetSecretsAsync(secretPaths);

            Console.WriteLine($"✅ Retrieved {secrets.Count} secrets:");
            foreach (var secret in secrets)
            {
                Console.WriteLine($"   - {secret.Key} (version: {secret.Value.Version})");
            }

            // Use secrets to configure application
            var appConfig = new ApplicationConfig
            {
                DatabaseHost = secrets.GetValueOrDefault("database/host")?.Value,
                DatabasePassword = secrets.GetValueOrDefault("database/password")?.Value,
                RedisConnectionString = secrets.GetValueOrDefault("redis/connection_string")?.Value,
                StripeApiKey = secrets.GetValueOrDefault("external_api/stripe_key")?.Value,
                SendGridApiKey = secrets.GetValueOrDefault("external_api/sendgrid_key")?.Value,
                JwtSigningKey = secrets.GetValueOrDefault("certificates/jwt_signing_key")?.Value
            };

            Console.WriteLine("✅ Application configuration loaded from secrets");

            // Clear sensitive values from memory
            foreach (var secret in secrets.Values)
            {
                secret.Clear();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Failed to load application secrets: {ex.Message}");
        }
    }

    /// <summary>
    /// Example: Secret rotation and versioning
    /// Demonstrates handling secret updates and version management
    /// </summary>
    public static async Task SecretRotationExample()
    {
        Console.WriteLine("\n=== Secret Rotation Example ===");

        var options = new SecureStoreOptions
        {
            ServerUrl = KeyVaultUrl,
            VerifySsl = true,
            UseMutualTls = true,
            ClientCertPath = "/opt/coyote/certs/client.crt",
            ClientKeyPath = "/opt/coyote/certs/client.key"
        };

        var authClient = AuthClientBuilder.CreateBuilder(AuthServerUrl, ClientId)
            .WithJwtBearerFlow("/opt/coyote/keys/jwt_private.pem", "key-id-123")
            .Build();

        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, authClient);

        try
        {
            var secretPath = "production/api/rotating_key";

            // Get current secret metadata to check rotation schedule
            var metadata = await client.GetSecretMetadataAsync(secretPath);
            if (metadata != null)
            {
                Console.WriteLine($"📋 Current secret version: {metadata.Version}");
                Console.WriteLine($"📋 Last updated: {metadata.UpdatedAt}");
                Console.WriteLine($"📋 Available versions: {string.Join(", ", metadata.AvailableVersions)}");

                // Check if rotation is needed (example: rotate every 30 days)
                var daysSinceUpdate = (DateTime.UtcNow - metadata.UpdatedAt).TotalDays;
                if (daysSinceUpdate > 30)
                {
                    Console.WriteLine("🔄 Secret is due for rotation");
                    
                    // Generate new secret value
                    var newSecretValue = GenerateSecureApiKey();
                    
                    // Store new version with rotation metadata
                    var rotationMetadata = new Dictionary<string, string>
                    {
                        ["rotated_at"] = DateTime.UtcNow.ToString("O"),
                        ["rotation_reason"] = "scheduled_30day",
                        ["previous_version"] = metadata.Version
                    };

                    var newVersion = await client.SetSecretAsync(secretPath, newSecretValue, rotationMetadata);
                    Console.WriteLine($"✅ Secret rotated to version: {newVersion}");
                }
                else
                {
                    Console.WriteLine($"ℹ️ Secret rotation not needed (last updated {daysSinceUpdate:F1} days ago)");
                }
            }

            // Always get the latest version
            var currentSecret = await client.GetSecretAsync(secretPath);
            if (currentSecret != null)
            {
                Console.WriteLine($"🔑 Using secret version: {currentSecret.Version}");
                
                // Use the secret
                await UseApiKeySecurely(currentSecret.Value);
                
                // Clear from memory
                currentSecret.Clear();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Secret rotation failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Example: Builder pattern with advanced configuration
    /// Shows fluent configuration for complex scenarios
    /// </summary>
    public static async Task AdvancedConfigurationExample()
    {
        Console.WriteLine("\n=== Advanced Configuration Example ===");

        try
        {
            // Build complex configuration using fluent API
            using var client = SecureStoreClientFactory.CreateBuilder(KeyVaultUrl)
                .WithApiVersion("v2") // Use newer API version
                .WithTimeout(45000) // 45 second timeout
                .WithRetry(maxAttempts: 5, backoffMs: 2000) // Aggressive retry
                .WithMutualTls("/opt/certs/client.crt", "/opt/certs/client.key")
                .WithTls(verifySsl: true, caCertPath: "/opt/certs/ca.crt")
                .WithDefaultNamespace("trading/production")
                .WithCustomHeaders(new Dictionary<string, string>
                {
                    ["X-Service-Name"] = "trading-engine",
                    ["X-Service-Version"] = "2.1.0",
                    ["X-Environment"] = "production"
                })
                .WithIntegratedAuth(auth =>
                {
                    auth.AuthMode = AuthMode.MutualTls;
                    auth.ServerUrl = AuthServerUrl;
                    auth.ClientId = ClientId;
                    auth.CertificatePath = "/opt/certs/client.crt";
                    auth.PrivateKeyPath = "/opt/certs/client.key";
                    auth.DefaultScopes = new List<string> { "keyvault.admin" };
                    auth.TimeoutMs = 30000;
                    auth.MaxRetryAttempts = 3;
                })
                .WithMetrics(enableMetrics: true)
                .WithLogging(enableLogging: true)
                .Build();

            // Test advanced features
            var healthStatus = await client.GetHealthStatusAsync();
            if (healthStatus?.IsHealthy == true)
            {
                Console.WriteLine($"✅ KeyVault health: {healthStatus.Status}");
                Console.WriteLine($"   Details: {string.Join(", ", healthStatus.Details)}");
            }

            // List all secrets in our namespace
            var secretList = await client.ListSecretsAsync();
            Console.WriteLine($"📁 Found {secretList.Count} secrets in namespace");

            // Work with high-value secrets that require extra security
            var criticalSecrets = new[]
            {
                "master_encryption_key",
                "database_admin_password", 
                "root_ca_private_key"
            };

            foreach (var secretPath in criticalSecrets)
            {
                var secret = await client.GetSecretAsync(secretPath);
                if (secret != null)
                {
                    Console.WriteLine($"🔒 Retrieved critical secret: {secretPath}");
                    
                    // Use with extra care
                    await UseCriticalSecretSecurely(secret.Value);
                    
                    // Immediate cleanup
                    secret.Clear();
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Advanced configuration failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Example: Environment-based configuration
    /// Production-ready pattern using environment variables
    /// </summary>
    public static async Task EnvironmentConfigurationExample()
    {
        Console.WriteLine("\n=== Environment Configuration Example ===");

        try
        {
            // Load configuration from environment variables
            // Typical for containerized deployments
            using var client = SecureStoreClientFactory.CreateFromEnvironment();

            Console.WriteLine($"✅ Created client from environment for: {client.ServerUrl}");

            // Health check
            if (await client.TestConnectionAsync())
            {
                Console.WriteLine("✅ Connection test passed");
            }
            else
            {
                Console.WriteLine("❌ Connection test failed");
                return;
            }

            // Example: Load secrets for a microservice
            var serviceName = Environment.GetEnvironmentVariable("SERVICE_NAME") ?? "unknown-service";
            var environment = Environment.GetEnvironmentVariable("ENVIRONMENT") ?? "development";
            
            var secretPaths = new[]
            {
                $"{environment}/{serviceName}/database_url",
                $"{environment}/{serviceName}/api_key",
                $"{environment}/shared/monitoring_token"
            };

            var secrets = await client.GetSecretsAsync(secretPaths);
            
            Console.WriteLine($"🔧 Loaded {secrets.Count} configuration secrets for {serviceName}");
            
            // Configure the microservice
            foreach (var secret in secrets)
            {
                // In real application, you'd set these in your configuration system
                Console.WriteLine($"   Setting config: {secret.Key.Split('/').Last()}");
            }

            // Cleanup
            foreach (var secret in secrets.Values)
            {
                secret.Clear();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Environment configuration failed: {ex.Message}");
            Console.WriteLine("💡 Ensure these environment variables are set:");
            Console.WriteLine("   - KEYVAULT_URL");
            Console.WriteLine("   - AUTH_SERVER_URL");
            Console.WriteLine("   - AUTH_CLIENT_ID");
            Console.WriteLine("   - AUTH_CLIENT_SECRET (or cert paths)");
        }
    }

    /// <summary>
    /// Example: Secret monitoring and alerts
    /// Demonstrates proactive secret health monitoring
    /// </summary>
    public static async Task SecretMonitoringExample()
    {
        Console.WriteLine("\n=== Secret Monitoring Example ===");

        var options = new SecureStoreOptions
        {
            ServerUrl = KeyVaultUrl,
            EnableMetrics = true
        };

        var authClient = AuthClientBuilder.CreateBuilder(AuthServerUrl, ClientId)
            .WithClientCredentialsFlow(Environment.GetEnvironmentVariable("CLIENT_SECRET") ?? "demo-secret")
            .Build();

        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, authClient);

        try
        {
            // Monitor critical secrets
            var criticalSecrets = new[]
            {
                "production/database/master_password",
                "production/certificates/tls_private_key",
                "production/api/payment_gateway_key"
            };

            Console.WriteLine("🔍 Monitoring critical secrets...");

            foreach (var secretPath in criticalSecrets)
            {
                try
                {
                    var metadata = await client.GetSecretMetadataAsync(secretPath);
                    if (metadata != null)
                    {
                        var age = DateTime.UtcNow - metadata.UpdatedAt;
                        var status = age.TotalDays switch
                        {
                            > 90 => "🔴 CRITICAL - Secret is very old",
                            > 60 => "🟡 WARNING - Secret should be rotated soon",
                            > 30 => "🟠 INFO - Secret rotation due",
                            _ => "🟢 OK - Secret is fresh"
                        };

                        Console.WriteLine($"   {secretPath}: {status} (age: {age.TotalDays:F1} days)");

                        // Check for metadata indicators
                        if (metadata.Metadata.ContainsKey("expires_at"))
                        {
                            if (DateTime.TryParse(metadata.Metadata["expires_at"], out var expiryDate))
                            {
                                if (expiryDate < DateTime.UtcNow.AddDays(7))
                                {
                                    Console.WriteLine($"     ⚠️ Secret expires soon: {expiryDate}");
                                }
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine($"   {secretPath}: ❌ NOT FOUND");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"   {secretPath}: ❌ ERROR - {ex.Message}");
                }
            }

            // Overall health check
            var healthStatus = await client.GetHealthStatusAsync();
            if (healthStatus != null)
            {
                var healthIcon = healthStatus.IsHealthy ? "✅" : "❌";
                Console.WriteLine($"\n{healthIcon} KeyVault Health: {healthStatus.Status}");
                
                if (healthStatus.Details.ContainsKey("secrets_count"))
                {
                    Console.WriteLine($"📊 Total secrets: {healthStatus.Details["secrets_count"]}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Secret monitoring failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Run all SecureStoreClient examples
    /// </summary>
    public static async Task RunAllExamples()
    {
        Console.WriteLine("🔐 Running SecureStoreClient Examples");
        Console.WriteLine("=====================================");

        try
        {
            await BasicSecretRetrievalExample();
            await MultipleSecretsExample();
            await SecretRotationExample();
            await AdvancedConfigurationExample();
            await EnvironmentConfigurationExample();
            await SecretMonitoringExample();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Examples failed: {ex.Message}");
        }

        Console.WriteLine("\n✅ SecureStoreClient examples completed!");
    }

    // Helper methods for demonstration
    private static async Task UsePasswordSecurely(string password)
    {
        // Simulate secure usage
        await Task.Delay(100);
        Console.WriteLine($"   💾 Database connection established (password length: {password.Length})");
    }

    private static async Task UseApiKeySecurely(string apiKey)
    {
        // Simulate secure usage
        await Task.Delay(50);
        Console.WriteLine($"   🔑 API authenticated (key length: {apiKey.Length})");
    }

    private static async Task UseCriticalSecretSecurely(string secret)
    {
        // Simulate critical operation
        await Task.Delay(200);
        Console.WriteLine($"   🏛️ Critical operation completed (secret length: {secret.Length})");
    }

    private static string GenerateSecureApiKey()
    {
        // In production, use cryptographically secure random generation
        return Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
    }

    private class ApplicationConfig
    {
        public string? DatabaseHost { get; set; }
        public string? DatabasePassword { get; set; }
        public string? RedisConnectionString { get; set; }
        public string? StripeApiKey { get; set; }
        public string? SendGridApiKey { get; set; }
        public string? JwtSigningKey { get; set; }
    }
}
