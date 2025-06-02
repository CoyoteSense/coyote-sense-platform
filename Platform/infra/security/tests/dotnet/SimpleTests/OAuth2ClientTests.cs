// filepath: c:\CoyoteSense\coyote-sense-platform\Platform\infra\security\tests\dotnet\SimpleTests\OAuth2ClientTests.cs
using Coyote.Infra.Security.Tests.TestHelpers;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Http;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using Xunit;

namespace Coyote.Infra.Security.Tests.SimpleTests;

/// <summary>
/// Tests for different OAuth2 authentication flows
/// </summary>
public class OAuth2ClientTests
{    private readonly Microsoft.Extensions.Logging.ILogger<MockOAuth2HttpClient> _logger;
    private readonly MockOAuth2HttpClient _httpClient;
    private readonly InMemoryTokenStorage _tokenStorage;
    private readonly ConsoleAuthLogger _authLogger;
    
    public OAuth2ClientTests()
    {
        _logger = new Microsoft.Extensions.Logging.Abstractions.NullLogger<MockOAuth2HttpClient>();
        _httpClient = new MockOAuth2HttpClient(_logger);
        _tokenStorage = new InMemoryTokenStorage();
        _authLogger = new ConsoleAuthLogger();
    }
    
    [Fact]
    public async Task TestClientCredentialsFlow()
    {
        // Arrange
        var config = new AuthClientConfig
        {
            ServerUrl = "https://test-auth.example.com",
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            DefaultScopes = new List<string> { "api.read", "api.write" },
            AutoRefresh = true
        };
        var client = new AuthClient(config, _httpClient, _tokenStorage, _authLogger);
        
        // Act
        var result = await client.AuthenticateClientCredentialsAsync();
        
        // Assert
        Assert.NotNull(result);
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Token);
        Assert.NotEmpty(result.Token!.AccessToken);
        Assert.Equal("Bearer", result.Token.TokenType);
    }
    
    [Fact]
    public async Task TestRefreshToken()
    {
        // Arrange
        var config = new AuthClientConfig
        {
            ServerUrl = "https://test-auth.example.com",
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            DefaultScopes = new List<string> { "api.read", "api.write" },
            AutoRefresh = true
        };
        var client = new AuthClient(config, _httpClient, _tokenStorage, _authLogger);
        
        // First authenticate to get a token with refresh token
        var authResult = await client.AuthenticateClientCredentialsAsync();
        Assert.True(authResult.IsSuccess);
        Assert.NotNull(authResult.Token?.RefreshToken);
        
        // Act - refresh the token
        var refreshResult = await client.RefreshTokenAsync(authResult.Token!.RefreshToken!);
        
        // Assert
        Assert.NotNull(refreshResult);
        Assert.True(refreshResult.IsSuccess);
        Assert.NotNull(refreshResult.Token);
        Assert.NotEmpty(refreshResult.Token!.AccessToken);
        Assert.NotEqual(authResult.Token.AccessToken, refreshResult.Token.AccessToken);
    }
    
    [Fact]
    public async Task TestIntrospectToken()
    {
        // Arrange
        var config = new AuthClientConfig
        {
            ServerUrl = "https://test-auth.example.com",
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            DefaultScopes = new List<string> { "api.read", "api.write" },
            AutoRefresh = true
        };
        var client = new AuthClient(config, _httpClient, _tokenStorage, _authLogger);
        
        // First authenticate to get a token
        var authResult = await client.AuthenticateClientCredentialsAsync();
        Assert.True(authResult.IsSuccess);        // Act - introspect the token
        var isActive = await client.IntrospectTokenAsync(authResult.Token!.AccessToken);
        
        // Assert
        Assert.True(isActive);
    }
    
    [Fact]
    public async Task TestRevokeToken()
    {
        // Arrange
        var config = new AuthClientConfig
        {
            ServerUrl = "https://test-auth.example.com",
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            DefaultScopes = new List<string> { "api.read", "api.write" },
            AutoRefresh = true
        };
        var client = new AuthClient(config, _httpClient, _tokenStorage, _authLogger);
        
        // First authenticate to get a token
        var authResult = await client.AuthenticateClientCredentialsAsync();
        Assert.True(authResult.IsSuccess);
          // Act - revoke the token
        var revokeResult = await client.RevokeTokenAsync(authResult.Token!.AccessToken);
        
        // Assert
        Assert.True(revokeResult);
          // Token should no longer be valid
        var isTokenActive = await client.IntrospectTokenAsync(authResult.Token!.AccessToken);
        Assert.False(isTokenActive);
    }
    
    [Fact]
    public async Task TestGetValidToken()
    {
        // Arrange
        var config = new AuthClientConfig
        {
            ServerUrl = "https://test-auth.example.com",
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            DefaultScopes = new List<string> { "api.read", "api.write" },
            AutoRefresh = true
        };
        var client = new AuthClient(config, _httpClient, _tokenStorage, _authLogger);
        
        // First authenticate to get a token
        var authResult = await client.AuthenticateClientCredentialsAsync();
        Assert.True(authResult.IsSuccess);
        
        // Act - get a valid token (should return existing token)
        var validToken = await client.GetValidTokenAsync();
        
        // Assert
        Assert.NotNull(validToken);
        Assert.Equal(authResult.Token!.AccessToken, validToken.AccessToken);
    }
}
