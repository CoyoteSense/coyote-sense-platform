using System;
using System.Threading.Tasks;
using Xunit;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;

namespace Coyote.Infra.Security.Tests.Unit;

/// <summary>
/// Tests for Auth Client implementations without using the factory
/// </summary>
public class AuthClientDirectTests
{    /// <summary>
    /// Test that MockAuthClient can be created and used directly
    /// </summary>
    [Fact]
    public void MockClient_ShouldBeCreatable()
    {
        // Arrange
        var options = new AuthClientOptions
        {
            ClientId = "test-client",
            ClientSecret = "test-secret",
            BaseUrl = "https://test.example.com"
        };
        
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<Coyote.Infra.Security.Auth.Modes.Mock.MockAuthClient>.Instance;
        
        // Act
        var client = new Coyote.Infra.Security.Auth.Modes.Mock.MockAuthClient(options, logger);
        
        // Assert
        Assert.NotNull(client);
        Assert.False(client.IsAuthenticated);
        Assert.Null(client.CurrentToken);
    }
      /// <summary>
    /// Test that MockAuthClient can authenticate with client credentials
    /// </summary>
    [Fact]
    public async Task MockClient_ShouldAuthenticateWithClientCredentials()
    {
        // Arrange
        var options = new AuthClientOptions
        {
            ClientId = "test-client",
            ClientSecret = "test-secret",
            BaseUrl = "https://test.example.com"
        };
        
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<Coyote.Infra.Security.Auth.Modes.Mock.MockAuthClient>.Instance;
        var client = new Coyote.Infra.Security.Auth.Modes.Mock.MockAuthClient(options, logger);
        
        // Act
        var result = await client.AuthenticateClientCredentialsAsync();
        
        // Assert
        Assert.True(result.IsSuccess);
        Assert.True(client.IsAuthenticated);
        Assert.NotNull(client.CurrentToken);
    }    /// <summary>
    /// Test that MockAuthClient can test connection
    /// </summary>
    [Fact]
    public async Task MockClient_ShouldTestConnection()
    {
        // Arrange
        var options = new AuthClientOptions
        {
            ClientId = "test-client",
            ClientSecret = "test-secret",
            BaseUrl = "https://test.example.com"
        };
        
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<Coyote.Infra.Security.Auth.Modes.Mock.MockAuthClient>.Instance;
        var client = new Coyote.Infra.Security.Auth.Modes.Mock.MockAuthClient(options, logger);
        
        // Act
        var result = await client.TestConnectionAsync();
        
        // Assert
        Assert.True(result);
    }
      /// <summary>
    /// Test that MockAuthClient can get server info
    /// </summary>
    [Fact]
    public async Task MockClient_ShouldGetServerInfo()
    {
        // Arrange
        var options = new AuthClientOptions
        {
            ClientId = "test-client",
            ClientSecret = "test-secret",
            BaseUrl = "https://test.example.com"
        };
        
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<Coyote.Infra.Security.Auth.Modes.Mock.MockAuthClient>.Instance;
        var client = new Coyote.Infra.Security.Auth.Modes.Mock.MockAuthClient(options, logger);
        
        // Act
        var result = await client.GetServerInfoAsync();
        
        // Assert
        Assert.NotNull(result);
    }
    
    /// <summary>
    /// Test that MockAuthClient can clear tokens
    /// </summary>
    [Fact]
    public async Task MockClient_ShouldClearTokens()
    {
        // Arrange
        var options = new AuthClientOptions
        {
            ClientId = "test-client",
            ClientSecret = "test-secret",
            BaseUrl = "https://test.example.com"
        };
        
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<Coyote.Infra.Security.Auth.Modes.Mock.MockAuthClient>.Instance;
        var client = new Coyote.Infra.Security.Auth.Modes.Mock.MockAuthClient(options, logger);
        
        // Authenticate first
        await client.AuthenticateClientCredentialsAsync();
        Assert.True(client.IsAuthenticated);
        
        // Act
        client.ClearTokens();
        
        // Assert
        Assert.False(client.IsAuthenticated);
        Assert.Null(client.CurrentToken);
    }
}
