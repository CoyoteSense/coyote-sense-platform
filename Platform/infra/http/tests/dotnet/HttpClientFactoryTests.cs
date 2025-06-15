using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Factory;
using Coyote.Infra.Http.Modes.Mock;
using Coyote.Infra.Http.Modes.Real;
using Coyote.Infra.Http.Modes.Debug;
using FluentAssertions;
using Moq;
using Xunit;

namespace Coyote.Infra.Http.Tests;

/// <summary>
/// Unit tests for HTTP client factory
/// </summary>
public class HttpClientFactoryTests
{
    private readonly Mock<IServiceProvider> _mockServiceProvider;
    private readonly Mock<IOptions<HttpClientOptions>> _mockHttpOptions;
    private readonly Mock<IOptions<HttpClientModeOptions>> _mockModeOptions;
    private readonly Mock<ILogger<HttpClientFactory>> _mockLogger;
    private readonly HttpClientFactory _factory;    public HttpClientFactoryTests()
    {
        _mockServiceProvider = new Mock<IServiceProvider>();
        _mockHttpOptions = new Mock<IOptions<HttpClientOptions>>();
        _mockModeOptions = new Mock<IOptions<HttpClientModeOptions>>();
        _mockLogger = new Mock<ILogger<HttpClientFactory>>();        // Setup default options
        _mockHttpOptions.Setup(x => x.Value).Returns(new HttpClientOptions());        _mockModeOptions.Setup(x => x.Value).Returns(new HttpClientModeOptions { 
            Mode = RuntimeMode.Production,
            Mock = new MockModeOptions(),
            Debug = new DebugModeOptions()
        });

        // Create real instances instead of mocking them since they have dependencies
        var httpOptions = Options.Create(new HttpClientOptions());        var modeOptions = Options.Create(new HttpClientModeOptions 
        { 
            Mode = RuntimeMode.Production,
            Mock = new MockModeOptions(),
            Debug = new DebugModeOptions()
        });

        var mockLogger = new Mock<ILogger<MockHttpClient>>();
        var realLogger = new Mock<ILogger<RealHttpClient>>();
        var debugLogger = new Mock<ILogger<DebugHttpClient>>();
        
        var mockHttpClient = new MockHttpClient(httpOptions, modeOptions, mockLogger.Object);
        var realHttpClient = new RealHttpClient(httpOptions, realLogger.Object);
        var debugHttpClient = new DebugHttpClient(httpOptions, modeOptions, debugLogger.Object, _mockServiceProvider.Object);

        _mockServiceProvider.Setup(x => x.GetService(typeof(MockHttpClient)))
            .Returns(mockHttpClient);
        _mockServiceProvider.Setup(x => x.GetService(typeof(RealHttpClient)))
            .Returns(realHttpClient);
        _mockServiceProvider.Setup(x => x.GetService(typeof(DebugHttpClient)))
            .Returns(debugHttpClient);

        _factory = new HttpClientFactory(
            _mockServiceProvider.Object,
            _mockModeOptions.Object,
            _mockHttpOptions.Object,
            _mockLogger.Object);
    }[Fact]
    public void CreateHttpClientForMode_Testing_ShouldReturnMockClient()
    {
        // Act
        var client = _factory.CreateHttpClientForMode(RuntimeMode.Testing);

        // Assert
        client.Should().NotBeNull();
        client.Should().BeOfType<MockHttpClient>();
    }

    [Fact]
    public void CreateHttpClientForMode_Production_ShouldReturnRealClient()
    {
        // Act
        var client = _factory.CreateHttpClientForMode(RuntimeMode.Production);

        // Assert
        client.Should().NotBeNull();
        client.Should().BeOfType<RealHttpClient>();
    }    [Theory]
    [InlineData("testing", RuntimeMode.Testing)]
    [InlineData("TESTING", RuntimeMode.Testing)]
    [InlineData("Testing", RuntimeMode.Testing)]
    [InlineData("production", RuntimeMode.Production)]
    [InlineData("PRODUCTION", RuntimeMode.Production)]
    [InlineData("Production", RuntimeMode.Production)]
    public void GetCurrentMode_WithEnvironmentVariable_ShouldReturnCorrectMode(string envValue, RuntimeMode expectedMode)
    {
        // Arrange
        Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", envValue);

        try
        {
            // Act
            var mode = _factory.GetCurrentMode();

            // Assert
            mode.Should().Be(expectedMode);
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", null);
        }
    }    [Fact]
    public void GetCurrentMode_WithModeEnvironmentVariable_ShouldReturnCorrectMode()
    {
        // Arrange
        Environment.SetEnvironmentVariable("MODE", "testing");

        try
        {
            // Act
            var mode = _factory.GetCurrentMode();

            // Assert
            mode.Should().Be(RuntimeMode.Testing);
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable("MODE", null);
        }
    }    [Fact]
    public void GetCurrentMode_WithNoEnvironmentVariable_ShouldReturnConfiguredMode()
    {
        // Arrange
        Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", null);
        Environment.SetEnvironmentVariable("MODE", null);
          var mockModeOptions = new Mock<IOptions<HttpClientModeOptions>>();
        mockModeOptions.Setup(x => x.Value).Returns(new HttpClientModeOptions { Mode = RuntimeMode.Debug });
        
        var factory = new HttpClientFactory(
            _mockServiceProvider.Object,
            mockModeOptions.Object,
            _mockHttpOptions.Object,
            _mockLogger.Object);

        // Act
        var mode = factory.GetCurrentMode();

        // Assert
        mode.Should().Be(RuntimeMode.Debug);
    }    [Fact]
    public void CreateHttpClient_ShouldReturnClientBasedOnCurrentMode()
    {
        // Arrange
        Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "testing");

        try
        {
            // Act
            var client = _factory.CreateClient();

            // Assert
            client.Should().NotBeNull();
            client.Should().BeOfType<MockHttpClient>();
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", null);
        }
    }    [Fact]
    public void GetCurrentMode_WithInvalidEnvironmentVariable_ShouldReturnConfiguredMode()
    {
        // Arrange
        Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "invalid_mode");

        try
        {
            // Act
            var mode = _factory.GetCurrentMode();

            // Assert
            mode.Should().Be(RuntimeMode.Production); // Default from configuration
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", null);
        }
    }
}
