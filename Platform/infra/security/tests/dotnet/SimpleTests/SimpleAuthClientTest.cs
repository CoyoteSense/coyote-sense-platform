using Coyote.Infra.Security.Tests.TestHelpers;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Http;
using Microsoft.Extensions.Logging;
using Xunit;
using System.Threading.Tasks;

namespace Coyote.Infra.Security.Tests.SimpleTests;

/// <summary>
/// Simple test to verify our OAuth2 client works
/// </summary>
public class SimpleAuthClientTest
{
    [Fact]
    public async Task TestOAuth2ClientWithMock()
    {
        // Arrange
        var logger = new Microsoft.Extensions.Logging.Abstractions.NullLogger<MockOAuth2HttpClient>();
        var httpClient = new MockOAuth2HttpClient(logger);
        var config = new AuthClientConfig
        {
            ServerUrl = "https://test-auth.example.com",
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            DefaultScopes = new System.Collections.Generic.List<string> { "api.read", "api.write" },
            AutoRefresh = true
        };
        var tokenStorage = new InMemoryTokenStorage();
        var client = new AuthClient(config, httpClient, tokenStorage, new ConsoleAuthLogger());
        
        // Act
        var result = await client.AuthenticateClientCredentialsAsync();
        
        // Assert
        Assert.NotNull(result);
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Token);
        Assert.NotEmpty(result.Token!.AccessToken);
        Assert.Equal("Bearer", result.Token.TokenType);
    }
}

/// <summary>
/// A simple in-memory token storage implementation for testing
/// </summary>
public class InMemoryTokenStorage : IAuthTokenStorage
{
    private readonly Dictionary<string, AuthToken> _tokens = new();

    public Task<AuthToken?> GetTokenAsync(string key)
    {
        _tokens.TryGetValue(key, out var token);
        return Task.FromResult(token);
    }

    public Task StoreTokenAsync(string key, AuthToken token)
    {
        _tokens[key] = token;
        return Task.CompletedTask;
    }
    
    public Task ClearTokenAsync(string key)
    {
        _tokens.Remove(key);
        return Task.CompletedTask;
    }
    
    public AuthToken? GetToken(string clientId)
    {
        _tokens.TryGetValue(clientId, out var token);
        return token;
    }
    
    public void ClearToken(string clientId)
    {
        _tokens.Remove(clientId);
    }
    
    public void ClearAllTokens()
    {
        _tokens.Clear();
    }
}
