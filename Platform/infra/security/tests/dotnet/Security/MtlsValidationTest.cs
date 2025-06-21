using Xunit;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Auth.Options;

namespace Coyote.Infra.Security.Tests;

/// <summary>
/// Simple verification test for mTLS validation fix
/// </summary>
public class MtlsValidationTest
{
    [Fact]
    public void AuthClientConfig_MtlsMode_ShouldNotRequireClientSecret()
    {
        // Arrange
        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentialsMtls,
            ServerUrl = "https://test.example.com",
            ClientId = "test-client",
            ClientCertPath = "/path/to/cert.pem",
            ClientKeyPath = "/path/to/key.pem"
            // Note: No ClientSecret set
        };

        // Act
        var isValid = config.IsValid();

        // Assert
        Assert.True(isValid, "mTLS configuration should be valid without ClientSecret");
    }

    [Fact]
    public void MtlsOptions_ToAuthClientConfig_ShouldCreateValidConfig()
    {
        // Arrange
        var options = new MtlsOptions
        {
            ServerUrl = "https://test.example.com",
            ClientId = "test-client",
            ClientCertPath = "/path/to/cert.pem",
            ClientKeyPath = "/path/to/key.pem",
            CaCertPath = "/path/to/ca.pem"
        };

        // Act
        var config = options.ToAuthClientConfig();

        // Assert
        Assert.True(config.IsValid(), "Config created from MtlsOptions should be valid");
        Assert.Equal(AuthMode.ClientCredentialsMtls, config.AuthMode);
        Assert.Null(config.ClientSecret); // Should not set client secret for mTLS
    }

    [Fact]
    public void AuthClientConfig_RequiresClientSecret_ShouldReturnFalseForMtls()
    {
        // Arrange
        var config = new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentialsMtls,
            ServerUrl = "https://test.example.com",
            ClientId = "test-client",
            ClientCertPath = "/path/to/cert.pem",
            ClientKeyPath = "/path/to/key.pem"
        };

        // Act
        var requiresSecret = config.RequiresClientSecret();

        // Assert
        Assert.False(requiresSecret, "mTLS mode should not require client secret");
    }
}
