using System;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Auth.Modes.Real;

namespace Coyote.Infra.Security.Tests.Unit;

/// <summary>
/// Simple tests to verify the cleaned up test structure works
/// </summary>
public class SimpleWorkingTests
{
    [Fact]
    public void AuthClientOptions_Validation_ShouldWork()
    {
        // Arrange
        var options = new AuthClientOptions
        {
            BaseUrl = "https://test.example.com",
            ClientId = "test-client",
            ClientSecret = "test-secret"
        };

        // Act
        Action validateAction = () => options.Validate();

        // Assert
        validateAction.Should().NotThrow();
    }

    [Fact]
    public void AuthClientOptions_InvalidUrl_ShouldThrow()
    {
        // Arrange
        var options = new AuthClientOptions
        {
            BaseUrl = "", // Invalid
            ClientId = "test-client",
            ClientSecret = "test-secret"
        };

        // Act & Assert
        Action validateAction = () => options.Validate();
        validateAction.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AuthMode_Enum_ShouldHaveExpectedValues()
    {
        // Assert
        Enum.IsDefined(typeof(AuthMode), AuthMode.ClientCredentials).Should().BeTrue();
        Enum.IsDefined(typeof(AuthMode), AuthMode.ClientCredentialsMtls).Should().BeTrue();
        Enum.IsDefined(typeof(AuthMode), AuthMode.JwtBearer).Should().BeTrue();
        Enum.IsDefined(typeof(AuthMode), AuthMode.AuthorizationCode).Should().BeTrue();
    }

    [Fact]
    public void RealAuthClient_Constructor_WithValidOptions_ShouldNotThrow()
    {
        // Arrange
        var options = new AuthClientOptions
        {
            BaseUrl = "https://test.example.com",
            ClientId = "test-client",
            ClientSecret = "test-secret"
        };
        
        var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        var logger = loggerFactory.CreateLogger<RealAuthClient>();

        // Act & Assert
        Action createAction = () => new RealAuthClient(options, logger);
        createAction.Should().NotThrow();
    }
}
