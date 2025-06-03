using Xunit;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Modes.Mock;
using Microsoft.Extensions.Logging;

namespace StandaloneMockTest;

public class MockHttpClientTest
{
    [Fact]
    public void TestMockHttpClient_Should_Initialize_Correctly()
    {
        // Arrange
        var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        var logger = loggerFactory.CreateLogger<MockHttpClient>();

        var modeOptions = new HttpClientModeOptions
        {
            Mode = HttpClientMode.Mock
        };

        var mockOptions = new MockResponseOptions
        {
            Responses = new List<MockResponse>
            {
                new MockResponse
                {
                    Url = "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
                    Method = "POST",
                    StatusCode = 200,
                    Content = @"{
                        ""access_token"": ""test_access_token"",
                        ""token_type"": ""Bearer"",
                        ""expires_in"": 3600
                    }",
                    Headers = new Dictionary<string, string>
                    {
                        ["Content-Type"] = "application/json"
                    }
                }
            }
        };

        // Act
        var mockHttpClient = new MockHttpClient(modeOptions, mockOptions, logger);

        // Assert
        Assert.NotNull(mockHttpClient);
        Assert.IsAssignableFrom<ICoyoteHttpClient>(mockHttpClient);
    }

    [Fact]
    public async Task TestMockHttpClient_Should_Return_Mock_Response()
    {
        // Arrange
        var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        var logger = loggerFactory.CreateLogger<MockHttpClient>();

        var modeOptions = new HttpClientModeOptions
        {
            Mode = HttpClientMode.Mock
        };

        var mockOptions = new MockResponseOptions
        {
            Responses = new List<MockResponse>
            {
                new MockResponse
                {
                    Url = "https://test.example.com/api/test",
                    Method = "GET",
                    StatusCode = 200,
                    Content = @"{""message"": ""Hello from mock!""}",
                    Headers = new Dictionary<string, string>
                    {
                        ["Content-Type"] = "application/json"
                    }
                }
            }
        };

        var mockHttpClient = new MockHttpClient(modeOptions, mockOptions, logger);

        // Act
        var response = await mockHttpClient.GetAsync("https://test.example.com/api/test");

        // Assert
        Assert.NotNull(response);
        Assert.Equal(200, (int)response.StatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("Hello from mock!", content);
    }
}
