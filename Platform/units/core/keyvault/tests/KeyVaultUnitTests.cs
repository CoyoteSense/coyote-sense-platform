using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Xunit;
using Coyote.Units.KeyVault.Services;

namespace Coyote.Units.KeyVault.Tests
{
    public class KeyVaultUnitTests
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthService> _authLogger;
        private readonly ILogger<SecretService> _secretLogger;

        public KeyVaultUnitTests()
        {
            _configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string>
                {
                    ["MasterKey"] = "test-master-key"
                })
                .Build();

            _authLogger = LoggerFactory.Create(builder => builder.AddConsole())
                .CreateLogger<AuthService>();
            
            _secretLogger = LoggerFactory.Create(builder => builder.AddConsole())
                .CreateLogger<SecretService>();
        }

        [Fact]
        public async Task AuthService_Authenticate_ShouldReturnValidToken()
        {
            // Arrange
            var authService = new AuthService(_configuration, _authLogger);
            await authService.InitializeAsync();

            var credentials = new UnitCredentials
            {
                UnitId = "test-unit",
                UnitRole = "test-role"
            };

            // Act
            var token = await authService.AuthenticateAsync(credentials);

            // Assert
            Assert.NotNull(token);
            Assert.NotEmpty(token.Token);
            Assert.Equal("test-unit", token.UnitId);
            Assert.Equal("test-role", token.UnitRole);
            Assert.True(token.ExpiresAt > DateTime.UtcNow);
        }

        [Fact]
        public async Task AuthService_ValidateToken_ShouldReturnValidResult()
        {
            // Arrange
            var authService = new AuthService(_configuration, _authLogger);
            await authService.InitializeAsync();

            var credentials = new UnitCredentials
            {
                UnitId = "test-unit",
                UnitRole = "test-role"
            };

            var token = await authService.AuthenticateAsync(credentials);

            // Act
            var result = await authService.ValidateTokenAsync(token.Token);

            // Assert
            Assert.True(result.IsValid);
            Assert.Equal("test-unit", result.UnitId);
            Assert.Equal("test-role", result.UnitRole);
        }

        [Fact]
        public async Task SecretService_GetSecret_ShouldReturnSecret()
        {
            // Arrange
            var secretService = new SecretService(_configuration, _secretLogger);
            await secretService.InitializeAsync();

            // Act
            var secret = await secretService.GetSecretAsync("database/password", "test-unit");

            // Assert
            Assert.Equal("mock-db-password", secret);
        }

        [Fact]
        public async Task SecretService_SetSecret_ShouldStoreSecret()
        {
            // Arrange
            var secretService = new SecretService(_configuration, _secretLogger);
            await secretService.InitializeAsync();

            // Act
            var success = await secretService.SetSecretAsync("test/secret", "test-value", "test-unit");

            // Assert
            Assert.True(success);

            // Verify the secret was stored
            var retrievedSecret = await secretService.GetSecretAsync("test/secret", "test-unit");
            Assert.Equal("test-value", retrievedSecret);
        }

        [Fact]
        public async Task SecretService_DeleteSecret_ShouldRemoveSecret()
        {
            // Arrange
            var secretService = new SecretService(_configuration, _secretLogger);
            await secretService.InitializeAsync();

            // Store a secret first
            await secretService.SetSecretAsync("test/delete", "test-value", "test-unit");

            // Act
            var success = await secretService.DeleteSecretAsync("test/delete", "test-unit");

            // Assert
            Assert.True(success);

            // Verify the secret was deleted
            await Assert.ThrowsAsync<KeyNotFoundException>(
                () => secretService.GetSecretAsync("test/delete", "test-unit"));
        }
    }
} 