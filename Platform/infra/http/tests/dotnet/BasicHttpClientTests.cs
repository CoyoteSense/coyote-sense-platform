using Xunit;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Factory;

namespace Coyote.Infra.Http.Tests;

/// <summary>
/// Basic tests for HTTP client functionality
/// </summary>
public class BasicHttpClientTests
{
    [Fact]
    public void HttpRequest_Should_Create_With_DefaultValues()
    {
        // Arrange & Act
        var request = new HttpRequest();

        // Assert
        request.Method.Should().Be(HttpMethod.Get);
        request.Url.Should().Be(string.Empty);
        request.Body.Should().BeNull();
        request.Headers.Should().NotBeNull().And.BeEmpty();
        request.VerifyPeer.Should().BeTrue();
        request.FollowRedirects.Should().BeTrue();
    }

    [Fact]
    public void HttpRequest_SetHeader_Should_AddHeader()
    {
        // Arrange
        var request = new HttpRequest();
        const string headerName = "Authorization";
        const string headerValue = "Bearer token123";

        // Act
        request.SetHeader(headerName, headerValue);

        // Assert
        request.Headers.Should().ContainKey(headerName);
        request.Headers[headerName].Should().Be(headerValue);
    }

    [Fact]
    public void HttpRequest_SetJsonBody_Should_SerializeContent()
    {
        // Arrange
        var request = new HttpRequest();
        var content = new { Name = "Test", Value = 123 };

        // Act
        request.SetJsonBody(content);

        // Assert
        request.Body.Should().NotBeNullOrEmpty();
        request.Headers.Should().ContainKey("Content-Type");
        request.Headers["Content-Type"].Should().Be("application/json");
    }

    [Fact]
    public void HttpResponse_IsSuccess_Should_ReturnTrue_ForSuccessStatusCodes()
    {
        // Arrange
        var response = new HttpResponse { StatusCode = 200 };

        // Act & Assert
        response.IsSuccess.Should().BeTrue();
        
        // Test other success codes
        var response201 = new HttpResponse { StatusCode = 201 };
        response201.IsSuccess.Should().BeTrue();
        
        var response299 = new HttpResponse { StatusCode = 299 };
        response299.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void HttpResponse_IsSuccess_Should_ReturnFalse_ForErrorStatusCodes()
    {
        // Arrange
        var response404 = new HttpResponse { StatusCode = 404 };
        var response500 = new HttpResponse { StatusCode = 500 };

        // Act & Assert
        response404.IsSuccess.Should().BeFalse();
        response500.IsSuccess.Should().BeFalse();
    }

    [Fact]
    public void RuntimeMode_Enum_Should_HaveExpectedValues()
    {
        // Act & Assert
        Enum.IsDefined(typeof(RuntimeMode), RuntimeMode.Production).Should().BeTrue();
        Enum.IsDefined(typeof(RuntimeMode), RuntimeMode.Testing).Should().BeTrue();
        Enum.IsDefined(typeof(RuntimeMode), RuntimeMode.Debug).Should().BeTrue();
        Enum.IsDefined(typeof(RuntimeMode), RuntimeMode.Recording).Should().BeTrue();
        Enum.IsDefined(typeof(RuntimeMode), RuntimeMode.Replay).Should().BeTrue();
        Enum.IsDefined(typeof(RuntimeMode), RuntimeMode.Simulation).Should().BeTrue();
    }
}
