using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Moq;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Auth.Clients;
using Coyote.Infra.Security.Auth.Options;
using Coyote.Infra.Security.Auth.Factory;

namespace Coyote.Infra.Security.Tests.Unit;

/// <summary>
/// Unit tests for SecureStoreClient
/// Tests core functionality with mocked dependencies
/// </summary>
public class SecureStoreClientTests : IDisposable
{
    private readonly Mock<IAuthClient> _mockAuthClient;
    private readonly Mock<ILogger<SecureStoreClient>> _mockLogger;
    private readonly SecureStoreOptions _defaultOptions;

    public SecureStoreClientTests()
    {
        _mockAuthClient = new Mock<IAuthClient>();
        _mockLogger = new Mock<ILogger<SecureStoreClient>>();
        
        _defaultOptions = new SecureStoreOptions
        {
            ServerUrl = "https://keyvault.test.com",
            ApiVersion = "v1",
            TimeoutMs = 5000,
            MaxRetryAttempts = 2,
            VerifySsl = false // For testing
        };
    }

    [Fact]
    public void Constructor_WithValidOptions_ShouldInitializeSuccessfully()
    {
        // Act
        using var client = new SecureStoreClient(_defaultOptions, _mockAuthClient.Object, _mockLogger.Object);

        // Assert
        Assert.Equal(_defaultOptions.ServerUrl, client.ServerUrl);
        Assert.False(client.IsAuthenticated); // No token initially
    }

    [Fact]
    public void Constructor_WithNullOptions_ShouldThrowArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => 
            new SecureStoreClient(null!, _mockAuthClient.Object));
    }

    [Fact]
    public void Constructor_WithNullAuthClient_ShouldThrowArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => 
            new SecureStoreClient(_defaultOptions, (IAuthClient)null!));
    }

    [Fact]
    public void Constructor_WithInvalidOptions_ShouldThrowArgumentException()
    {
        // Arrange
        var invalidOptions = new SecureStoreOptions
        {
            ServerUrl = "", // Invalid
            TimeoutMs = -1  // Invalid
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            new SecureStoreClient(invalidOptions, _mockAuthClient.Object));
    }

    [Fact]
    public async Task GetSecretAsync_WithEmptyPath_ShouldThrowArgumentException()
    {
        // Arrange
        using var client = new SecureStoreClient(_defaultOptions, _mockAuthClient.Object);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() => 
            client.GetSecretAsync(""));
    }

    [Fact]
    public async Task GetSecretAsync_WithValidPath_WhenAuthClientReturnsToken_ShouldAttemptRequest()
    {
        // Arrange
        var mockToken = new AuthToken
        {
            AccessToken = "test-token",
            ExpiresAt = DateTime.UtcNow.AddHours(1)
        };

        _mockAuthClient.Setup(x => x.GetValidTokenAsync(It.IsAny<CancellationToken>()))
                      .ReturnsAsync(mockToken);

        using var client = new SecureStoreClient(_defaultOptions, _mockAuthClient.Object);

        // Act & Assert
        // This will fail due to no actual HTTP server, but we can verify auth client was called
        var exception = await Assert.ThrowsAsync<SecureStoreException>(() => 
            client.GetSecretAsync("test/secret"));

        // Verify auth client was called
        _mockAuthClient.Verify(x => x.GetValidTokenAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task GetSecretAsync_WhenAuthClientReturnsNoToken_ShouldThrowSecureStoreException()
    {
        // Arrange
        _mockAuthClient.Setup(x => x.GetValidTokenAsync(It.IsAny<CancellationToken>()))
                      .ReturnsAsync((AuthToken?)null);

        using var client = new SecureStoreClient(_defaultOptions, _mockAuthClient.Object);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<SecureStoreException>(() => 
            client.GetSecretAsync("test/secret"));

        Assert.Equal("AUTH_TOKEN_MISSING", exception.ErrorCode);
    }

    [Fact]
    public async Task SetSecretAsync_WithEmptyPath_ShouldThrowArgumentException()
    {
        // Arrange
        using var client = new SecureStoreClient(_defaultOptions, _mockAuthClient.Object);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() => 
            client.SetSecretAsync("", "value"));
    }

    [Fact]
    public async Task SetSecretAsync_WithEmptyValue_ShouldThrowArgumentException()
    {
        // Arrange
        using var client = new SecureStoreClient(_defaultOptions, _mockAuthClient.Object);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() => 
            client.SetSecretAsync("test/secret", ""));
    }

    [Fact]
    public async Task DeleteSecretAsync_WithEmptyPath_ShouldThrowArgumentException()
    {
        // Arrange
        using var client = new SecureStoreClient(_defaultOptions, _mockAuthClient.Object);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() => 
            client.DeleteSecretAsync(""));
    }

    [Fact]
    public async Task GetSecretsAsync_WithEmptyList_ShouldReturnEmptyDictionary()
    {
        // Arrange
        using var client = new SecureStoreClient(_defaultOptions, _mockAuthClient.Object);

        // Act
        var result = await client.GetSecretsAsync(new List<string>());

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetSecretsAsync_WithNullList_ShouldThrowArgumentNullException()
    {
        // Arrange
        using var client = new SecureStoreClient(_defaultOptions, _mockAuthClient.Object);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(() => 
            client.GetSecretsAsync(null!));
    }

    [Fact]
    public void IsAuthenticated_WithoutToken_ShouldReturnFalse()
    {
        // Arrange
        using var client = new SecureStoreClient(_defaultOptions, _mockAuthClient.Object);

        // Act & Assert
        Assert.False(client.IsAuthenticated);
    }

    [Fact]
    public async Task TestConnectionAsync_ShouldCallAuthClientForToken()
    {
        // Arrange
        var mockToken = new AuthToken
        {
            AccessToken = "test-token",
            ExpiresAt = DateTime.UtcNow.AddHours(1)
        };

        _mockAuthClient.Setup(x => x.GetValidTokenAsync(It.IsAny<CancellationToken>()))
                      .ReturnsAsync(mockToken);

        using var client = new SecureStoreClient(_defaultOptions, _mockAuthClient.Object);

        // Act
        var result = await client.TestConnectionAsync();

        // Assert
        // Will be false due to no HTTP server, but auth client should be called
        Assert.False(result);
        _mockAuthClient.Verify(x => x.GetValidTokenAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public void Dispose_ShouldNotThrow()
    {
        // Arrange
        var client = new SecureStoreClient(_defaultOptions, _mockAuthClient.Object);

        // Act & Assert
        client.Dispose(); // Should not throw
        client.Dispose(); // Multiple dispose should be safe
    }

    public void Dispose()
    {
        _mockAuthClient?.Dispose();
    }
}

/// <summary>
/// Unit tests for SecureStoreClientFactory
/// </summary>
public class SecureStoreClientFactoryTests
{
    private readonly Mock<IAuthClient> _mockAuthClient;
    private readonly SecureStoreOptions _validOptions;

    public SecureStoreClientFactoryTests()
    {
        _mockAuthClient = new Mock<IAuthClient>();
        _validOptions = new SecureStoreOptions
        {
            ServerUrl = "https://keyvault.test.com",
            TimeoutMs = 5000
        };
    }

    [Fact]
    public void CreateWithAuthClient_WithValidParameters_ShouldReturnClient()
    {
        // Act
        using var client = SecureStoreClientFactory.CreateWithAuthClient(_validOptions, _mockAuthClient.Object);

        // Assert
        Assert.NotNull(client);
        Assert.Equal(_validOptions.ServerUrl, client.ServerUrl);
    }

    [Fact]
    public void CreateWithAuthClient_WithNullOptions_ShouldThrowArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => 
            SecureStoreClientFactory.CreateWithAuthClient(null!, _mockAuthClient.Object));
    }

    [Fact]
    public void CreateWithAuthClient_WithNullAuthClient_ShouldThrowArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => 
            SecureStoreClientFactory.CreateWithAuthClient(_validOptions, null!));
    }

    [Fact]
    public void CreateWithTokenProvider_WithValidParameters_ShouldReturnClient()
    {
        // Arrange
        Task<string?> tokenProvider(CancellationToken ct) => Task.FromResult<string?>("test-token");

        // Act
        using var client = SecureStoreClientFactory.CreateWithTokenProvider(_validOptions, tokenProvider);

        // Assert
        Assert.NotNull(client);
        Assert.Equal(_validOptions.ServerUrl, client.ServerUrl);
    }

    [Fact]
    public void CreateWithTokenProvider_WithNullProvider_ShouldThrowArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => 
            SecureStoreClientFactory.CreateWithTokenProvider(_validOptions, null!));
    }

    [Fact]
    public void CreateBuilder_WithValidServerUrl_ShouldReturnBuilder()
    {
        // Act
        var builder = SecureStoreClientFactory.CreateBuilder("https://keyvault.test.com");

        // Assert
        Assert.NotNull(builder);
    }

    [Fact]
    public void Builder_WithAuthClient_ShouldBuildSuccessfully()
    {
        // Act
        using var client = SecureStoreClientFactory.CreateBuilder("https://keyvault.test.com")
            .WithAuthClient(_mockAuthClient.Object)
            .WithTimeout(5000)
            .WithRetry(2)
            .Build();

        // Assert
        Assert.NotNull(client);
        Assert.Equal("https://keyvault.test.com", client.ServerUrl);
    }

    [Fact]
    public void Builder_WithTokenProvider_ShouldBuildSuccessfully()
    {
        // Arrange
        Task<string?> tokenProvider(CancellationToken ct) => Task.FromResult<string?>("test-token");

        // Act
        using var client = SecureStoreClientFactory.CreateBuilder("https://keyvault.test.com")
            .WithTokenProvider(tokenProvider)
            .WithTimeout(5000)
            .Build();

        // Assert
        Assert.NotNull(client);
    }

    [Fact]
    public void Builder_WithoutAuthOrTokenProvider_ShouldThrowInvalidOperationException()
    {
        // Act & Assert
        var builder = SecureStoreClientFactory.CreateBuilder("https://keyvault.test.com")
            .WithTimeout(5000);

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Builder_WithMutualTls_ShouldConfigureCorrectly()
    {
        // Arrange
        Task<string?> tokenProvider(CancellationToken ct) => Task.FromResult<string?>("test-token");

        // Act
        using var client = SecureStoreClientFactory.CreateBuilder("https://keyvault.test.com")
            .WithTokenProvider(tokenProvider)
            .WithMutualTls("/path/to/cert.pem", "/path/to/key.pem")
            .WithTls(verifySsl: true, caCertPath: "/path/to/ca.pem")
            .Build();

        // Assert
        Assert.NotNull(client);
    }

    [Fact]
    public void Builder_WithCustomHeaders_ShouldConfigureCorrectly()
    {
        // Arrange
        Task<string?> tokenProvider(CancellationToken ct) => Task.FromResult<string?>("test-token");
        var customHeaders = new Dictionary<string, string>
        {
            ["X-Custom-Header"] = "custom-value",
            ["X-Another-Header"] = "another-value"
        };

        // Act
        using var client = SecureStoreClientFactory.CreateBuilder("https://keyvault.test.com")
            .WithTokenProvider(tokenProvider)
            .WithCustomHeaders(customHeaders)
            .Build();

        // Assert
        Assert.NotNull(client);
    }
}
