using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Auth.Options;
using Coyote.Infra.Security.Auth.Security;
using Coyote.Infra.Security.Extensions;
using Coyote.Infra.Http;
using Coyote.Infra.Security.Tests.TestHelpers;

namespace Coyote.Infra.Security.Tests;

/// <summary>
/// Comprehensive tests for enhanced authentication client factory
/// Validates new options pattern, security features, and DI integration
/// </summary>
public class EnhancedAuthClientFactoryTests
{
    private readonly ITestOutputHelper _output;

    public EnhancedAuthClientFactoryTests(ITestOutputHelper output)
    {
        _output = output;
    }    [Fact]
    public void CreateFromOptions_WithValidMtlsOptions_ShouldCreateClient()
    {        // Arrange
        var options = new MtlsOptions
        {
            ServerUrl = "https://auth.example.com",
            ClientId = "test-client",
            ClientCertPath = "/path/to/cert.crt",
            ClientKeyPath = "/path/to/key.key",
            CaCertPath = "/path/to/ca.crt", // Add required CA cert path
            DefaultScopes = new List<string> { "test.scope" }
        };        // Act
        using var client = TestAuthClientFactory.CreateFromOptions(options);

        // Assert
        Assert.NotNull(client);
        Assert.IsAssignableFrom<IAuthClient>(client);
        _output.WriteLine("✅ mTLS client created successfully with options pattern");
    }

    [Fact]
    public void CreateFromOptions_WithInvalidOptions_ShouldThrowValidationException()
    {
        // Arrange
        var invalidOptions = new MtlsOptions
        {
            // Missing required ServerUrl
            ClientId = "test-client",
            ClientCertPath = "/path/to/cert.crt",
            ClientKeyPath = "/path/to/key.key"
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            TestAuthClientFactory.CreateFromOptions(invalidOptions));

        Assert.Contains("ServerUrl", exception.Message);
        _output.WriteLine("✅ Validation correctly rejected invalid options");
    }

    [Fact]
    public void CreateFromOptions_WithClientCredentialsOptions_ShouldCreateClient()
    {
        // Arrange
        var options = new ClientCredentialsOptions
        {
            ServerUrl = "https://auth.example.com",
            ClientId = "test-client",
            ClientSecret = "test-secret",
            DefaultScopes = new List<string> { "api.read" },
            AutoRefresh = false, // Disabled to prevent background loops that cause hangs
            TimeoutMs = 30000
        };

        // Act
        using var client = TestAuthClientFactory.CreateFromOptions(options);

        // Assert
        Assert.NotNull(client);
        _output.WriteLine("✅ Client Credentials client created successfully");
    }

    [Fact]
    public void CreateFromOptions_WithJwtBearerOptions_ShouldCreateClient()
    {
        // Arrange
        var options = new JwtBearerOptions
        {
            ServerUrl = "https://auth.example.com",
            ClientId = "test-client",
            JwtSigningKeyPath = "/path/to/private.key",
            JwtIssuer = "test-issuer",
            JwtAudience = "test-audience",
            DefaultScopes = new List<string> { "jwt.scope" }
        };

        // Act
        using var client = TestAuthClientFactory.CreateFromOptions(options);

        // Assert
        Assert.NotNull(client);
        _output.WriteLine("✅ JWT Bearer client created successfully");
    }

    [Fact]
    public void CreateWithSecureCredentials_ShouldHandleSecureCredentials()
    {
        // Arrange
        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentials,
            ServerUrl = "https://auth.example.com",
            ClientId = "test-client",
            DefaultScopes = new List<string> { "api.read" }
        };

        using var credentialProvider = new SecureCredentialProvider();
        credentialProvider.SetClientSecret("secure-secret");

        // Act
        using var client = TestAuthClientFactory.CreateWithSecureCredentials(
            config, credentialProvider);

        // Assert
        Assert.NotNull(client);
        _output.WriteLine("✅ Client created with secure credential provider");
    }

    [Fact]
    public void SecureCredentialProvider_ShouldSecurelyHandleCredentials()
    {
        // Arrange
        const string testSecret = "my-super-secret-key";

        using var provider = new SecureCredentialProvider();

        // Act
        provider.SetClientSecret(testSecret);
        var retrievedSecret = provider.GetClientSecret();

        // Assert
        Assert.True(provider.HasClientSecret);
        Assert.Equal(testSecret, retrievedSecret);
        _output.WriteLine("✅ Secure credential provider working correctly");
    }

    [Fact]
    public void AuthOptionsExtensions_ShouldConvertOptionsToConfig()
    {
        // Arrange
        var mtlsOptions = new MtlsOptions
        {
            ServerUrl = "https://auth.example.com",
            ClientId = "test-client",
            ClientCertPath = "/cert.crt",
            ClientKeyPath = "/key.key",
            DefaultScopes = new List<string> { "test" },
            TimeoutMs = 45000,
            AutoRefresh = false
        };

        // Act
        var config = mtlsOptions.ToAuthClientConfig();

        // Assert
        Assert.Equal(AuthMode.ClientCredentialsMtls, config.AuthMode);
        Assert.Equal(mtlsOptions.ServerUrl, config.ServerUrl);
        Assert.Equal(mtlsOptions.ClientId, config.ClientId);
        Assert.Equal(mtlsOptions.ClientCertPath, config.ClientCertPath);
        Assert.Equal(mtlsOptions.ClientKeyPath, config.ClientKeyPath);
        Assert.Equal(mtlsOptions.TimeoutMs, config.TimeoutMs);
        Assert.Equal(mtlsOptions.AutoRefresh, config.AutoRefresh);
        _output.WriteLine("✅ Options to config conversion working correctly");
    }
    [Fact]
    public async Task ThreadSafeHttpClientFactory_ShouldBeThreadSafe()
    {        // Arrange & Act
        var tasks = new Task[10];
        var clients = new HttpClient[10];

        for (int i = 0; i < 10; i++)
        {
            int index = i;
            tasks[i] = Task.Run(() =>
            {
                clients[index] = TestAuthClientFactory.GetDefaultHttpClient();
            });
        }

        await Task.WhenAll(tasks);

        // Assert
        foreach (var client in clients)
        {
            Assert.NotNull(client);
        }
        _output.WriteLine("✅ Thread-safe HTTP client factory working correctly");
    }

    [Fact]
    public void DependencyInjection_ShouldRegisterServicesCorrectly()
    {
        // Arrange
        var services = new ServiceCollection(); var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth:ServerUrl"] = "https://auth.example.com",
                ["Auth:ClientId"] = "test-client",
                ["Auth:ClientSecret"] = "test-secret"
            })
            .Build();

        // Act        services.AddSingleton<IConfiguration>(configuration);
        services.AddLogging(); // Add logging services first
        services.AddAuthClientWithClientCredentials(options =>
        {
            options.ServerUrl = configuration["Auth:ServerUrl"]!;
            options.ClientId = configuration["Auth:ClientId"]!;
            options.ClientSecret = configuration["Auth:ClientSecret"]!;
            options.DefaultScopes = new List<string> { "api.read" };
        });
        services.AddAuthenticationServices();

        var serviceProvider = services.BuildServiceProvider();        // Assert
        var authClient = serviceProvider.GetService<IAuthClient>();
        var tokenStorage = serviceProvider.GetService<IAuthTokenStorage>();
        var authLogger = serviceProvider.GetService<IAuthLogger>();
        // Note: AuthClientPool was removed as per requirements

        Assert.NotNull(authClient);
        Assert.NotNull(tokenStorage);
        Assert.NotNull(authLogger);
        _output.WriteLine("✅ Dependency injection registration working correctly");    }

    [Fact]
    public void ModernFactoryMethods_ShouldWork()
    {
        // Arrange & Act
        var options = new ClientCredentialsOptions
        {
            ServerUrl = "https://auth.example.com",
            ClientId = "test-client",
            ClientSecret = "test-secret",
            DefaultScopes = new List<string> { "modern.scope" }
        };

        using var client = TestAuthClientFactory.CreateFromOptions(options);

        // Assert
        Assert.NotNull(client);
        _output.WriteLine("✅ Modern factory methods working correctly");
    }
}

/// <summary>
/// Integration tests for real authentication scenarios
/// </summary>
public class AuthClientIntegrationTests
{
    private readonly ITestOutputHelper _output;

    public AuthClientIntegrationTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact(Skip = "Integration test - requires real auth server")]
    public async Task MtlsAuthentication_WithRealServer_ShouldWork()
    {
        // This would be enabled for integration testing with a real auth server
        var options = new MtlsOptions
        {
            ServerUrl = "https://auth.coyotesense.io",
            ClientId = "integration-test-client",
            ClientCertPath = "/opt/coyote/certs/client.crt",
            ClientKeyPath = "/opt/coyote/certs/client.key",
            DefaultScopes = new List<string> { "test.scope" }
        };

        using var client = TestAuthClientFactory.CreateFromOptions(options);
        var result = await client.AuthenticateClientCredentialsAsync();

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Token);
        _output.WriteLine($"✅ Real mTLS authentication successful: {result.Token.AccessToken[..10]}...");
    }
}
