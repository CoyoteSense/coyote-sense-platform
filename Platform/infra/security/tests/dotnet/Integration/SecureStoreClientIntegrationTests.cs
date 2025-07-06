using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Auth.Options;
using Coyote.Infra.Security.Tests.Mocks;

namespace Coyote.Infra.Security.Tests.Integration;

/// <summary>
/// Integration tests for SecureStoreClient with mock KeyVault server
/// Tests end-to-end functionality with realistic HTTP interactions
/// </summary>
[Collection("IntegrationTests")]
public class SecureStoreClientIntegrationTests : IDisposable
{
    private readonly MockKeyVaultServer _mockServer;
    private readonly ILogger<Coyote.Infra.Security.Auth.SecureStoreClient> _logger;

    public SecureStoreClientIntegrationTests()
    {
        _mockServer = new MockKeyVaultServer();
        _logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<Coyote.Infra.Security.Auth.SecureStoreClient>();
    }

    [Fact]
    public async Task GetSecretAsync_WithValidSecret_ShouldReturnSecretValue()
    {
        // Arrange
        var secretPath = "test/database/password";
        var expectedValue = "super-secret-password";
        
        _mockServer.AddSecret(secretPath, expectedValue, new Dictionary<string, string>
        {
            ["environment"] = "test",
            ["created_by"] = "integration_test"
        });

        var options = new SecureStoreOptions
        {
            ServerUrl = _mockServer.BaseUrl,
            VerifySsl = false,
            TimeoutMs = 5000
        };

        var mockAuthClient = new MockAuthClient("valid-token", DateTime.UtcNow.AddHours(1));
        
        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, mockAuthClient, _logger);

        // Act
        var result = await client.GetSecretAsync(secretPath);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(secretPath, result.Path);
        Assert.Equal(expectedValue, result.Value);
        Assert.Equal("test", result.Metadata["environment"]);
        Assert.Equal("integration_test", result.Metadata["created_by"]);
        Assert.True(result.CreatedAt <= DateTime.UtcNow);
    }

    [Fact]
    public async Task GetSecretAsync_WithNonExistentSecret_ShouldReturnNull()
    {
        // Arrange
        var options = new SecureStoreOptions
        {
            ServerUrl = _mockServer.BaseUrl,
            VerifySsl = false
        };

        var mockAuthClient = new MockAuthClient("valid-token", DateTime.UtcNow.AddHours(1));
        
        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, mockAuthClient);

        // Act
        var result = await client.GetSecretAsync("non/existent/secret");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task SetSecretAsync_WithNewSecret_ShouldCreateAndReturnVersion()
    {
        // Arrange
        var secretPath = "test/new/secret";
        var secretValue = "new-secret-value";
        var metadata = new Dictionary<string, string>
        {
            ["purpose"] = "integration_test",
            ["expires"] = "2025-12-31"
        };

        var options = new SecureStoreOptions
        {
            ServerUrl = _mockServer.BaseUrl,
            VerifySsl = false
        };

        var mockAuthClient = new MockAuthClient("valid-token", DateTime.UtcNow.AddHours(1));
        
        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, mockAuthClient);

        // Act
        var version = await client.SetSecretAsync(secretPath, secretValue, metadata);

        // Assert
        Assert.NotNull(version);
        Assert.Equal("1", version); // First version

        // Verify the secret was stored
        var retrievedSecret = await client.GetSecretAsync(secretPath);
        Assert.NotNull(retrievedSecret);
        Assert.Equal(secretValue, retrievedSecret.Value);
        Assert.Equal("integration_test", retrievedSecret.Metadata["purpose"]);
    }

    [Fact]
    public async Task DeleteSecretAsync_WithExistingSecret_ShouldReturnTrue()
    {
        // Arrange
        var secretPath = "test/delete/me";
        _mockServer.AddSecret(secretPath, "delete-me-value");

        var options = new SecureStoreOptions
        {
            ServerUrl = _mockServer.BaseUrl,
            VerifySsl = false
        };

        var mockAuthClient = new MockAuthClient("valid-token", DateTime.UtcNow.AddHours(1));
        
        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, mockAuthClient);

        // Act
        var result = await client.DeleteSecretAsync(secretPath);

        // Assert
        Assert.True(result);

        // Verify the secret was deleted
        var retrievedSecret = await client.GetSecretAsync(secretPath);
        Assert.Null(retrievedSecret);
    }

    [Fact]
    public async Task DeleteSecretAsync_WithNonExistentSecret_ShouldReturnFalse()
    {
        // Arrange
        var options = new SecureStoreOptions
        {
            ServerUrl = _mockServer.BaseUrl,
            VerifySsl = false
        };

        var mockAuthClient = new MockAuthClient("valid-token", DateTime.UtcNow.AddHours(1));
        
        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, mockAuthClient);

        // Act
        var result = await client.DeleteSecretAsync("non/existent/secret");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task GetSecretsAsync_WithMultipleSecrets_ShouldReturnAllFound()
    {
        // Arrange
        var secrets = new Dictionary<string, string>
        {
            ["test/secret1"] = "value1",
            ["test/secret2"] = "value2",
            ["test/secret3"] = "value3",
            ["non/existent"] = "will-not-be-found"
        };

        // Add first 3 secrets to mock server
        foreach (var secret in secrets.Take(3))
        {
            _mockServer.AddSecret(secret.Key, secret.Value);
        }

        var options = new SecureStoreOptions
        {
            ServerUrl = _mockServer.BaseUrl,
            VerifySsl = false
        };

        var mockAuthClient = new MockAuthClient("valid-token", DateTime.UtcNow.AddHours(1));
        
        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, mockAuthClient);

        // Act
        var results = await client.GetSecretsAsync(secrets.Keys);

        // Assert
        Assert.Equal(3, results.Count); // Only 3 found
        Assert.True(results.ContainsKey("test/secret1"));
        Assert.True(results.ContainsKey("test/secret2"));
        Assert.True(results.ContainsKey("test/secret3"));
        Assert.False(results.ContainsKey("non/existent"));

        Assert.Equal("value1", results["test/secret1"].Value);
        Assert.Equal("value2", results["test/secret2"].Value);
        Assert.Equal("value3", results["test/secret3"].Value);
    }

    [Fact]
    public async Task ListSecretsAsync_WithPrefix_ShouldReturnMatchingSecrets()
    {
        // Arrange
        var secrets = new Dictionary<string, string>
        {
            ["prod/database/host"] = "prod-db-host",
            ["prod/database/password"] = "prod-db-pass",
            ["prod/api/key"] = "prod-api-key",
            ["dev/database/host"] = "dev-db-host",
            ["test/random"] = "test-value"
        };

        foreach (var secret in secrets)
        {
            _mockServer.AddSecret(secret.Key, secret.Value);
        }

        var options = new SecureStoreOptions
        {
            ServerUrl = _mockServer.BaseUrl,
            VerifySsl = false
        };

        var mockAuthClient = new MockAuthClient("valid-token", DateTime.UtcNow.AddHours(1));
        
        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, mockAuthClient);

        // Act
        var prodSecrets = await client.ListSecretsAsync("prod/");
        var allSecrets = await client.ListSecretsAsync();

        // Assert
        Assert.Equal(3, prodSecrets.Count);
        Assert.Contains("prod/database/host", prodSecrets);
        Assert.Contains("prod/database/password", prodSecrets);
        Assert.Contains("prod/api/key", prodSecrets);

        Assert.Equal(5, allSecrets.Count);
    }

    [Fact]
    public async Task GetSecretMetadataAsync_WithExistingSecret_ShouldReturnMetadata()
    {
        // Arrange
        var secretPath = "test/metadata/secret";
        var metadata = new Dictionary<string, string>
        {
            ["owner"] = "integration_tests",
            ["environment"] = "test",
            ["rotation_days"] = "30"
        };

        _mockServer.AddSecret(secretPath, "secret-value", metadata);

        var options = new SecureStoreOptions
        {
            ServerUrl = _mockServer.BaseUrl,
            VerifySsl = false
        };

        var mockAuthClient = new MockAuthClient("valid-token", DateTime.UtcNow.AddHours(1));
        
        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, mockAuthClient);

        // Act
        var result = await client.GetSecretMetadataAsync(secretPath);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(secretPath, result.Path);
        Assert.Equal("1", result.Version);
        Assert.Equal("integration_tests", result.Metadata["owner"]);
        Assert.Equal("test", result.Metadata["environment"]);
        Assert.Equal("30", result.Metadata["rotation_days"]);
        Assert.Single(result.AvailableVersions);
        Assert.Contains("1", result.AvailableVersions);
    }

    [Fact]
    public async Task TestConnectionAsync_WithValidServer_ShouldReturnTrue()
    {
        // Arrange
        var options = new SecureStoreOptions
        {
            ServerUrl = _mockServer.BaseUrl,
            VerifySsl = false
        };

        var mockAuthClient = new MockAuthClient("valid-token", DateTime.UtcNow.AddHours(1));
        
        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, mockAuthClient);

        // Act
        var result = await client.TestConnectionAsync();

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task GetHealthStatusAsync_ShouldReturnHealthStatus()
    {
        // Arrange
        var options = new SecureStoreOptions
        {
            ServerUrl = _mockServer.BaseUrl,
            VerifySsl = false
        };

        var mockAuthClient = new MockAuthClient("valid-token", DateTime.UtcNow.AddHours(1));
        
        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, mockAuthClient);

        // Act
        var result = await client.GetHealthStatusAsync();

        // Assert
        Assert.NotNull(result);
        Assert.True(result.IsHealthy);
        Assert.Equal("healthy", result.Status);
        Assert.True(result.CheckedAt <= DateTime.UtcNow);
    }

    [Fact]
    public async Task TokenExpiry_ShouldAutomaticallyRefresh()
    {
        // Arrange
        var options = new SecureStoreOptions
        {
            ServerUrl = _mockServer.BaseUrl,
            VerifySsl = false,
            TokenRefreshBufferSeconds = 30 // 30 seconds buffer to match BaseAuthClient behavior
        };

        // Start with expired token (well past expiry to ensure it's detected)
        var mockAuthClient = new MockAuthClient("expired-token", DateTime.UtcNow.AddMinutes(-5));
        _mockServer.AddSecret("test/secret", "test-value");
        
        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, mockAuthClient);

        // Update mock to return fresh token on next call
        mockAuthClient.UpdateToken("fresh-token", DateTime.UtcNow.AddHours(1));

        // Act
        var result = await client.GetSecretAsync("test/secret");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("test-value", result.Value);
        
        // Verify that auth client was called once and returned the fresh token
        Assert.Equal(1, mockAuthClient.GetTokenCallCount);
    }

    [Fact]
    public async Task AuthenticationFailure_ShouldThrowSecureStoreException()
    {
        // Arrange
        var options = new SecureStoreOptions
        {
            ServerUrl = _mockServer.BaseUrl,
            VerifySsl = false
        };

        var mockAuthClient = new MockAuthClient(null, DateTime.UtcNow); // No token
        
        using var client = SecureStoreClientFactory.CreateWithAuthClient(options, mockAuthClient);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<SecureStoreException>(() => 
            client.GetSecretAsync("test/secret"));

        Assert.Equal("AUTH_TOKEN_MISSING", exception.ErrorCode);
    }

    public void Dispose()
    {
        _mockServer?.Dispose();
    }
}
