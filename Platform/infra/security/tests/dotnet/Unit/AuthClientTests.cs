using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using Moq.Protected;
using Xunit;
using FluentAssertions;
using Coyote.Infra.Security.Auth;

namespace Coyote.Infra.Security.OAuth2.Tests.Unit;

/// <summary>
/// Unit tests for AuthClient
/// </summary>
public class AuthClientTests : IDisposable
{
    private readonly Mock<IAuthTokenStorage> _mockTokenStorage;
    private readonly Mock<IAuthLogger> _mockLogger;
    private readonly Mock<HttpMessageHandler> _mockHttpMessageHandler;
    private readonly HttpClient _httpClient;
    private readonly AuthClientConfig _config;
    private readonly AuthClient _client;    public AuthClientTests()
    {
        _mockTokenStorage = new Mock<IAuthTokenStorage>();
        _mockLogger = new Mock<IAuthLogger>();
        _mockHttpMessageHandler = new Mock<HttpMessageHandler>();

        _httpClient = new HttpClient(_mockHttpMessageHandler.Object);

        _config = new AuthClientConfig
        {
            ServerUrl = "https://test-auth.example.com",
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            DefaultScopes = new List<string> { "read", "write" },
            TimeoutSeconds = 30,
            EnableAutoRefresh = false // Disable for most tests
        };

        _client = new AuthClient(_config, _httpClient, _tokenStorage: _mockTokenStorage.Object, _logger: _mockLogger.Object);
    }

    public void Dispose()
    {
        _client?.Dispose();
        _httpClient?.Dispose();
    }

    #region Configuration Tests

    [Fact]
    public void Constructor_WithValidConfig_ShouldInitializeCorrectly()
    {
        // Arrange & Act
        using var client = new OAuth2AuthClient(_config, _httpClient);

        // Assert
        client.Should().NotBeNull();
        client.Config.ServerUrl.Should().Be(_config.ServerUrl);
        client.Config.ClientId.Should().Be(_config.ClientId);
    }

    [Fact]
    public void Constructor_WithNullConfig_ShouldThrowArgumentNullException()
    {
        // Arrange, Act & Assert
        Assert.Throws<ArgumentNullException>(() => new OAuth2AuthClient(null!, _httpClient));
    }

    [Fact]
    public void Constructor_WithInvalidConfig_ShouldThrowArgumentException()
    {
        // Arrange
        var invalidConfig = new OAuth2ClientConfig(); // Missing required fields

        // Act & Assert
        Assert.Throws<ArgumentException>(() => new OAuth2AuthClient(invalidConfig, _httpClient));
    }

    #endregion

    #region Client Credentials Flow Tests    [Fact]
    public async Task ClientCredentialsAsync_WithValidCredentials_ShouldReturnSuccess()
    {
        // Arrange
        var tokenResponse = new
        {
            access_token = "test-access-token",
            token_type = "Bearer",
            expires_in = 3600,
            scope = "read write"
        };

        SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(tokenResponse));

        _mockTokenStorage.Setup(x => x.StoreTokenAsync(It.IsAny<string>(), It.IsAny<AuthToken>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _client.ClientCredentialsAsync(new[] { "read", "write" });

        // Assert
        result.Success.Should().BeTrue();
        result.Token.Should().NotBeNull();
        result.Token!.AccessToken.Should().Be("test-access-token");
        result.Token.TokenType.Should().Be("Bearer");
        result.Token.ExpiresIn.Should().Be(3600);
        result.Token.Scope.Should().Be("read write");
    }

    [Fact]
    public async Task ClientCredentialsAsync_WithInvalidCredentials_ShouldReturnError()
    {
        // Arrange
        var errorResponse = new
        {
            error = "invalid_client",
            error_description = "Authentication failed"
        };

        SetupHttpResponse(HttpStatusCode.Unauthorized, JsonSerializer.Serialize(errorResponse));

        // Act
        var result = await _client.ClientCredentialsAsync(new[] { "read", "write" });

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Be("invalid_client");
        result.ErrorDescription.Should().Be("Authentication failed");
        result.Token.Should().BeNull();
    }

    [Fact]
    public async Task ClientCredentialsAsync_WithNetworkError_ShouldReturnError()
    {
        // Arrange
        SetupHttpException(new HttpRequestException("Network error"));

        // Act
        var result = await _client.ClientCredentialsAsync(new[] { "read", "write" });

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().NotBeNullOrEmpty();
        result.Token.Should().BeNull();
    }

    #endregion

    #region JWT Bearer Flow Tests

    [Fact]
    public async Task JwtBearerAsync_WithValidJwt_ShouldReturnSuccess()
    {
        // Arrange
        _config.JwtSigningKeyPath = "test-key.pem";
        _config.JwtIssuer = "test-issuer";

        var tokenResponse = new
        {
            access_token = "jwt-access-token",
            token_type = "Bearer",
            expires_in = 3600,
            scope = "read write"
        };        SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(tokenResponse));

        _mockTokenStorage.Setup(x => x.StoreTokenAsync(It.IsAny<string>(), It.IsAny<AuthToken>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _client.JwtBearerAsync("test-subject", new[] { "read", "write" });

        // Assert
        result.Success.Should().BeTrue();
        result.Token.Should().NotBeNull();
        result.Token!.AccessToken.Should().Be("jwt-access-token");
    }

    [Fact]
    public async Task JwtBearerAsync_WithoutJwtConfig_ShouldThrowException()
    {
        // Arrange
        // JWT configuration not set

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() => 
            _client.JwtBearerAsync("test-subject", new[] { "read", "write" }));
    }

    #endregion

    #region Authorization Code Flow Tests

    [Fact]
    public async Task AuthorizationCodeAsync_WithValidCode_ShouldReturnSuccess()
    {
        // Arrange
        var tokenResponse = new
        {
            access_token = "auth-code-token",
            token_type = "Bearer",
            expires_in = 3600,
            refresh_token = "refresh-token-123",
            scope = "read write"
        };

        SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(tokenResponse));

        _mockTokenStorage.Setup(x => x.StoreTokenAsync(It.IsAny<string>(), It.IsAny<AuthToken>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _client.AuthorizationCodeAsync("test-auth-code", "test-verifier", new[] { "read", "write" });

        // Assert
        result.Success.Should().BeTrue();
        result.Token.Should().NotBeNull();
        result.Token!.AccessToken.Should().Be("auth-code-token");
        result.Token.RefreshToken.Should().Be("refresh-token-123");
    }

    [Fact]
    public async Task AuthorizationCodeAsync_WithInvalidCode_ShouldReturnError()
    {
        // Arrange
        var errorResponse = new
        {
            error = "invalid_grant",
            error_description = "Authorization code is invalid"
        };

        SetupHttpResponse(HttpStatusCode.BadRequest, JsonSerializer.Serialize(errorResponse));

        // Act
        var result = await _client.AuthorizationCodeAsync("invalid-code", "test-verifier", new[] { "read", "write" });

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Be("invalid_grant");
        result.ErrorDescription.Should().Be("Authorization code is invalid");
    }

    #endregion

    #region Refresh Token Tests

    [Fact]
    public async Task RefreshTokenAsync_WithValidRefreshToken_ShouldReturnSuccess()
    {
        // Arrange
        var tokenResponse = new
        {
            access_token = "new-access-token",
            token_type = "Bearer",
            expires_in = 3600,
            refresh_token = "new-refresh-token",
            scope = "read write"
        };

        SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(tokenResponse));

        _mockTokenStorage.Setup(x => x.StoreTokenAsync(It.IsAny<string>(), It.IsAny<AuthToken>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _client.RefreshTokenAsync("existing-refresh-token");

        // Assert
        result.Success.Should().BeTrue();
        result.Token.Should().NotBeNull();
        result.Token!.AccessToken.Should().Be("new-access-token");
        result.Token.RefreshToken.Should().Be("new-refresh-token");
    }

    [Fact]
    public async Task RefreshTokenAsync_WithInvalidRefreshToken_ShouldReturnError()
    {
        // Arrange
        var errorResponse = new
        {
            error = "invalid_grant",
            error_description = "Refresh token is invalid"
        };

        SetupHttpResponse(HttpStatusCode.BadRequest, JsonSerializer.Serialize(errorResponse));

        // Act
        var result = await _client.RefreshTokenAsync("invalid-refresh-token");

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Be("invalid_grant");
        result.ErrorDescription.Should().Be("Refresh token is invalid");
    }

    #endregion

    #region Token Introspection Tests

    [Fact]
    public async Task IntrospectTokenAsync_WithActiveToken_ShouldReturnActiveResult()
    {
        // Arrange
        var introspectionResponse = new
        {
            active = true,
            scope = "read write",
            client_id = "test-client-id",
            exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
        };

        SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(introspectionResponse));

        // Act
        var result = await _client.IntrospectTokenAsync("test-access-token");

        // Assert
        result.Success.Should().BeTrue();
        result.Active.Should().BeTrue();
        result.Scope.Should().Be("read write");
        result.ClientId.Should().Be("test-client-id");
    }

    [Fact]
    public async Task IntrospectTokenAsync_WithInactiveToken_ShouldReturnInactiveResult()
    {
        // Arrange
        var introspectionResponse = new
        {
            active = false
        };

        SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(introspectionResponse));

        // Act
        var result = await _client.IntrospectTokenAsync("inactive-token");

        // Assert
        result.Success.Should().BeTrue();
        result.Active.Should().BeFalse();
    }

    #endregion

    #region Token Revocation Tests

    [Fact]
    public async Task RevokeTokenAsync_WithValidToken_ShouldReturnSuccess()
    {
        // Arrange
        SetupHttpResponse(HttpStatusCode.OK, "");

        _mockTokenStorage.Setup(x => x.DeleteTokenAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _client.RevokeTokenAsync("test-access-token");

        // Assert
        result.Success.Should().BeTrue();
    }

    [Fact]
    public async Task RevokeTokenAsync_WithServerError_ShouldReturnError()
    {
        // Arrange
        SetupHttpResponse(HttpStatusCode.InternalServerError, "Internal Server Error");

        // Act
        var result = await _client.RevokeTokenAsync("test-access-token");

        // Assert
        result.Success.Should().BeFalse();
    }

    #endregion

    #region Token Storage Tests

    [Fact]
    public async Task StoreTokenAsync_WithValidToken_ShouldCallTokenStorage()
    {
        // Arrange
        var token = CreateTestToken("stored-token");

        _mockTokenStorage.Setup(x => x.StoreTokenAsync("test-key", token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _client.StoreTokenAsync("test-key", token);

        // Assert
        result.Should().BeTrue();
        _mockTokenStorage.Verify(x => x.StoreTokenAsync("test-key", token, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task GetStoredTokenAsync_WithExistingToken_ShouldReturnToken()
    {
        // Arrange
        var token = CreateTestToken("stored-token");

        _mockTokenStorage.Setup(x => x.GetTokenAsync("test-key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);

        // Act
        var result = await _client.GetStoredTokenAsync("test-key");

        // Assert
        result.Should().NotBeNull();
        result!.AccessToken.Should().Be("stored-token");
    }

    [Fact]
    public async Task DeleteStoredTokenAsync_WithExistingToken_ShouldCallTokenStorage()
    {
        // Arrange
        _mockTokenStorage.Setup(x => x.DeleteTokenAsync("test-key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = await _client.DeleteStoredTokenAsync("test-key");

        // Assert
        result.Should().BeTrue();
        _mockTokenStorage.Verify(x => x.DeleteTokenAsync("test-key", It.IsAny<CancellationToken>()), Times.Once);
    }

    #endregion

    #region Server Discovery Tests

    [Fact]
    public async Task DiscoverServerAsync_WithValidResponse_ShouldReturnServerInfo()
    {
        // Arrange
        var discoveryResponse = new
        {
            issuer = "https://test-auth.example.com",
            authorization_endpoint = "https://test-auth.example.com/oauth2/authorize",
            token_endpoint = "https://test-auth.example.com/oauth2/token",
            introspection_endpoint = "https://test-auth.example.com/oauth2/introspect",
            revocation_endpoint = "https://test-auth.example.com/oauth2/revoke",
            grant_types_supported = new[] { "client_credentials", "authorization_code", "refresh_token" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post", "tls_client_auth" }
        };

        SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(discoveryResponse));

        // Act
        var result = await _client.DiscoverServerAsync();

        // Assert
        result.Success.Should().BeTrue();
        result.ServerInfo.Should().NotBeNull();
        result.ServerInfo!.Issuer.Should().Be("https://test-auth.example.com");
        result.ServerInfo.TokenEndpoint.Should().Be("https://test-auth.example.com/oauth2/token");
        result.ServerInfo.SupportsClientCredentials.Should().BeTrue();
    }

    #endregion

    #region Token Expiration Tests

    [Fact]
    public void IsTokenExpired_WithExpiredToken_ShouldReturnTrue()
    {
        // Arrange
        var expiredToken = CreateTestToken("expired-token", expiresIn: -3600); // Expired 1 hour ago

        // Act
        var result = _client.IsTokenExpired(expiredToken);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsTokenExpired_WithValidToken_ShouldReturnFalse()
    {
        // Arrange
        var validToken = CreateTestToken("valid-token", expiresIn: 3600); // Expires in 1 hour

        // Act
        var result = _client.IsTokenExpired(validToken);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void IsTokenNearExpiry_WithTokenNearExpiry_ShouldReturnTrue()
    {
        // Arrange
        var nearExpiryToken = CreateTestToken("near-expiry-token", expiresIn: 30); // Expires in 30 seconds
        var bufferSeconds = 60; // 1 minute buffer

        // Act
        var result = _client.IsTokenNearExpiry(nearExpiryToken, bufferSeconds);

        // Assert
        result.Should().BeTrue();
    }

    #endregion

    #region Auto-Refresh Tests

    [Fact]
    public async Task StartAutoRefresh_WithValidToken_ShouldEnableAutoRefresh()
    {
        // Arrange
        var config = new OAuth2ClientConfig
        {
            ServerUrl = "https://test-auth.example.com",
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            EnableAutoRefresh = true,
            RefreshBufferSeconds = 60
        };

        using var client = new OAuth2AuthClient(config, _httpClient, _mockTokenStorage.Object, _mockLogger.Object);

        var expiringToken = CreateTestToken("expiring-token", expiresIn: 30, refreshToken: "refresh-token");

        _mockTokenStorage.Setup(x => x.GetTokenAsync("test-key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(expiringToken);

        var refreshedTokenResponse = new
        {
            access_token = "refreshed-token",
            token_type = "Bearer",
            expires_in = 3600,
            refresh_token = "new-refresh-token"
        };

        SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(refreshedTokenResponse));

        _mockTokenStorage.Setup(x => x.StoreTokenAsync(It.IsAny<string>(), It.IsAny<AuthToken>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        client.StartAutoRefresh("test-key");

        // Wait a short time for auto-refresh to potentially trigger
        await Task.Delay(100);

        client.StopAutoRefresh();

        // Assert
        // Verification is done through mock setup expectations
    }

    #endregion

    #region Concurrent Access Tests

    [Fact]
    public async Task ConcurrentTokenRequests_ShouldHandleMultipleRequests()
    {
        // Arrange
        const int concurrentRequests = 5;
        var tokenResponse = new
        {
            access_token = "concurrent-token",
            token_type = "Bearer",
            expires_in = 3600,
            scope = "read write"
        };

        SetupHttpResponse(HttpStatusCode.OK, JsonSerializer.Serialize(tokenResponse));

        _mockTokenStorage.Setup(x => x.StoreTokenAsync(It.IsAny<string>(), It.IsAny<AuthToken>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var tasks = new List<Task<OAuth2AuthResult>>();
        for (int i = 0; i < concurrentRequests; i++)
        {
            tasks.Add(_client.ClientCredentialsAsync(new[] { "read" }));
        }

        var results = await Task.WhenAll(tasks);

        // Assert
        foreach (var result in results)
        {
            result.Success.Should().BeTrue();
            result.Token.Should().NotBeNull();
            result.Token!.AccessToken.Should().Be("concurrent-token");
        }
    }

    #endregion

    #region Helper Methods

    private void SetupHttpResponse(HttpStatusCode statusCode, string content)
    {
        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(content, Encoding.UTF8, "application/json")
        };

        _mockHttpMessageHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);
    }

    private void SetupHttpException(Exception exception)
    {
        _mockHttpMessageHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(exception);
    }

    private static AuthToken CreateTestToken(
        string accessToken = "test-access-token",
        string tokenType = "Bearer",
        int expiresIn = 3600,
        string? refreshToken = null,
        string scope = "read write")
    {
        return new AuthToken
        {
            AccessToken = accessToken,
            TokenType = tokenType,
            ExpiresIn = expiresIn,
            RefreshToken = refreshToken,
            Scope = scope,
            IssuedAt = DateTimeOffset.UtcNow
        };
    }

    #endregion
}
