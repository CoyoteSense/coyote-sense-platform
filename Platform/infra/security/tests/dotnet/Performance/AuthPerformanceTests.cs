using System.Diagnostics;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NBomber.CSharp;
using Xunit;
using Xunit.Abstractions;
using CoyoteSense.OAuth2.Client.Tests.Mocks;
using Coyote.Infra.Security.Auth;

namespace CoyoteSense.OAuth2.Client.Tests.Performance;

/// <summary>
/// Performance tests for AuthClient using NBomber
/// </summary>
public class AuthPerformanceTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly MockOAuth2Server _mockServer;
    private readonly ServiceProvider _serviceProvider;
    private readonly IAuthClient _client;
    private bool _disposed;    public AuthPerformanceTests(ITestOutputHelper output)
    {
        _output = output;
        _mockServer = new MockOAuth2Server();
        
        var config = new AuthClientConfig
        {
            ServerUrl = _mockServer.BaseUrl,
            ClientId = "test-client",
            ClientSecret = "test-secret",
            Scope = "api.read api.write",
            EnableAutoRefresh = true,
            RetryPolicy = new AuthRetryPolicy
            {
                MaxRetries = 3,
                BaseDelay = TimeSpan.FromMilliseconds(100),
                MaxDelay = TimeSpan.FromSeconds(5)
            }
        };

        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Warning));
        services.AddHttpClient();        services.AddSingleton(config);
        services.AddTransient<IAuthTokenStorage, InMemoryTokenStorage>();
        services.AddTransient<IAuthClient, AuthClient>();
        
        _serviceProvider = services.BuildServiceProvider();
        _client = _serviceProvider.GetRequiredService<IAuthClient>();
    }

    [Fact]
    [Trait("Category", "Performance")]
    public async Task ClientCredentialsFlow_ShouldHandleHighConcurrency()
    {        // Arrange
        const int concurrentUsers = 50;
        const int requestsPerUser = 10;
        var results = new List<AuthToken>();
        var tasks = new List<Task<AuthToken>>();

        var stopwatch = Stopwatch.StartNew();

        // Act - Create concurrent authentication requests
        for (int i = 0; i < concurrentUsers; i++)
        {
            for (int j = 0; j < requestsPerUser; j++)
            {
                tasks.Add(_client.AuthenticateClientCredentialsAsync());
            }
        }

        var completedResults = await Task.WhenAll(tasks);
        stopwatch.Stop();

        // Assert
        completedResults.Should().HaveCount(concurrentUsers * requestsPerUser);
        completedResults.Should().AllSatisfy(result =>
        {
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.AccessToken.Should().NotBeNullOrEmpty();
        });

        var totalRequests = concurrentUsers * requestsPerUser;
        var duration = stopwatch.Elapsed;
        var requestsPerSecond = totalRequests / duration.TotalSeconds;

        _output.WriteLine($"Performance Results:");
        _output.WriteLine($"Total Requests: {totalRequests}");
        _output.WriteLine($"Duration: {duration.TotalMilliseconds:F2} ms");
        _output.WriteLine($"Requests/Second: {requestsPerSecond:F2}");
        _output.WriteLine($"Average Response Time: {duration.TotalMilliseconds / totalRequests:F2} ms");

        // Performance assertions
        requestsPerSecond.Should().BeGreaterThan(10, "Should handle at least 10 requests per second");
        duration.Should().BeLessThan(TimeSpan.FromSeconds(30), "Should complete within 30 seconds");
    }

    [Fact]
    [Trait("Category", "Performance")]
    public async Task TokenIntrospection_ShouldMaintainPerformanceUnderLoad()
    {
        // Arrange - Get some tokens first
        var tokens = new List<string>();
        for (int i = 0; i < 10; i++)
        {
            var result = await _client.AuthenticateClientCredentialsAsync();
            result.IsSuccess.Should().BeTrue();
            tokens.Add(result.AccessToken!);
        }        const int concurrentRequests = 100;
        var tasks = new List<Task<AuthTokenIntrospection>>();
        var stopwatch = Stopwatch.StartNew();

        // Act - Perform concurrent introspection requests
        for (int i = 0; i < concurrentRequests; i++)
        {
            var token = tokens[i % tokens.Count];
            tasks.Add(_client.IntrospectTokenAsync(token));
        }

        var results = await Task.WhenAll(tasks);
        stopwatch.Stop();

        // Assert
        results.Should().HaveCount(concurrentRequests);
        results.Should().AllSatisfy(result =>
        {
            result.Should().NotBeNull();
            result.Active.Should().BeTrue();
        });

        var requestsPerSecond = concurrentRequests / stopwatch.Elapsed.TotalSeconds;
        
        _output.WriteLine($"Introspection Performance Results:");
        _output.WriteLine($"Total Requests: {concurrentRequests}");
        _output.WriteLine($"Duration: {stopwatch.Elapsed.TotalMilliseconds:F2} ms");
        _output.WriteLine($"Requests/Second: {requestsPerSecond:F2}");

        requestsPerSecond.Should().BeGreaterThan(20, "Should handle at least 20 introspection requests per second");
    }

    [Fact]
    [Trait("Category", "Performance")]
    public async Task MemoryUsage_ShouldRemainStableUnderLoad()
    {
        // Arrange
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        
        var initialMemory = GC.GetTotalMemory(false);
        const int iterations = 1000;

        // Act - Perform many authentication requests
        for (int i = 0; i < iterations; i++)
        {
            var result = await _client.AuthenticateClientCredentialsAsync();
            result.IsSuccess.Should().BeTrue();

            // Perform introspection and revocation periodically
            if (i % 10 == 0)
            {
                await _client.IntrospectTokenAsync(result.AccessToken!);
                await _client.RevokeTokenAsync(result.AccessToken!);
            }

            // Force garbage collection every 100 iterations
            if (i % 100 == 0)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }

        // Force final garbage collection
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        
        var finalMemory = GC.GetTotalMemory(false);
        var memoryIncrease = finalMemory - initialMemory;
        var memoryIncreasePerRequest = memoryIncrease / (double)iterations;

        _output.WriteLine($"Memory Usage Results:");
        _output.WriteLine($"Initial Memory: {initialMemory / 1024:N0} KB");
        _output.WriteLine($"Final Memory: {finalMemory / 1024:N0} KB");
        _output.WriteLine($"Memory Increase: {memoryIncrease / 1024:N0} KB");
        _output.WriteLine($"Memory per Request: {memoryIncreasePerRequest:F2} bytes");

        // Assert memory usage is reasonable
        memoryIncreasePerRequest.Should().BeLessThan(1024, "Memory usage per request should be less than 1KB");
        memoryIncrease.Should().BeLessThan(50 * 1024 * 1024, "Total memory increase should be less than 50MB");
    }

    [Fact]
    [Trait("Category", "Performance")]
    public void NBomberLoadTest_ClientCredentialsFlow()
    {
        // Arrange
        var scenario = Scenario.Create("oauth2_client_credentials", async context =>
        {
            try
            {
                var result = await _client.AuthenticateClientCredentialsAsync();
                
                if (result.IsSuccess)
                {
                    return Response.Ok();
                }
                else
                {
                    return Response.Fail($"Authentication failed: {result.ErrorDescription}");
                }
            }
            catch (Exception ex)
            {
                return Response.Fail($"Exception: {ex.Message}");
            }
        })
        .WithLoadSimulations(
            Simulation.InjectPerSec(rate: 10, during: TimeSpan.FromSeconds(30))
        );

        // Act & Assert
        var stats = NBomberRunner
            .RegisterScenarios(scenario)
            .WithReportFolder("oauth2_performance_reports")
            .WithReportFormats(ReportFormat.Html, ReportFormat.Csv)
            .Run();

        // Assert performance metrics
        var clientCredentialsStats = stats.AllScenarioStats.First(s => s.ScenarioName == "oauth2_client_credentials");
        
        clientCredentialsStats.Ok.Request.Count.Should().BeGreaterThan(250, "Should complete at least 250 successful requests");
        clientCredentialsStats.Fail.Request.Count.Should().BeLessThan(10, "Should have less than 10 failed requests");
        clientCredentialsStats.Ok.Request.Mean.Should().BeLessThan(TimeSpan.FromMilliseconds(500), "Average response time should be less than 500ms");
        
        _output.WriteLine($"NBomber Results:");
        _output.WriteLine($"Successful Requests: {clientCredentialsStats.Ok.Request.Count}");
        _output.WriteLine($"Failed Requests: {clientCredentialsStats.Fail.Request.Count}");
        _output.WriteLine($"Average Response Time: {clientCredentialsStats.Ok.Request.Mean.TotalMilliseconds:F2} ms");
        _output.WriteLine($"95th Percentile: {clientCredentialsStats.Ok.Request.Percentile95.TotalMilliseconds:F2} ms");
    }

    [Fact]
    [Trait("Category", "Performance")]
    public async Task AutoRefresh_ShouldNotCausePerformanceDegradation()
    {
        // Arrange - Create a configuration with very short token expiry for testing
        var shortExpiryConfig = new OAuth2ClientConfiguration
        {
            ServerUrl = _mockServer.BaseUrl,
            ClientId = "test-client",
            ClientSecret = "test-secret",
            Scope = "api.read",
            EnableAutoRefresh = true,
            TokenRefreshThreshold = TimeSpan.FromSeconds(1)
        };        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Warning));
        services.AddHttpClient();
        services.AddSingleton(shortExpiryConfig);
        services.AddTransient<IAuthTokenStorage, InMemoryTokenStorage>();
        services.AddTransient<IAuthClient, AuthClient>();

        using var serviceProvider = services.BuildServiceProvider();
        var autoRefreshClient = serviceProvider.GetRequiredService<IAuthClient>();

        var stopwatch = Stopwatch.StartNew();
        const int requests = 50;

        // Act - Make requests that should trigger auto-refresh
        for (int i = 0; i < requests; i++)
        {
            var result = await autoRefreshClient.AuthenticateClientCredentialsAsync();
            result.IsSuccess.Should().BeTrue();

            // Small delay to allow potential token expiry
            await Task.Delay(100);
        }

        stopwatch.Stop();

        // Assert
        var averageTime = stopwatch.Elapsed.TotalMilliseconds / requests;
        
        _output.WriteLine($"Auto-refresh Performance:");
        _output.WriteLine($"Total Requests: {requests}");
        _output.WriteLine($"Total Time: {stopwatch.Elapsed.TotalMilliseconds:F2} ms");
        _output.WriteLine($"Average Time per Request: {averageTime:F2} ms");

        averageTime.Should().BeLessThan(200, "Auto-refresh should not significantly impact performance");
    }

    [Fact]
    [Trait("Category", "Performance")]
    public async Task ConcurrentClientsWithSharedTokenStorage_ShouldScale()
    {        // Arrange - Create multiple clients sharing the same token storage
        var sharedTokenStorage = new InMemoryTokenStorage();var clients = new List<IAuthClient>();

        for (int i = 0; i < 10; i++)
        {
            var services = new ServiceCollection();
            services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Warning));
            services.AddHttpClient();
            services.AddSingleton(new AuthClientConfig
            {
                ServerUrl = _mockServer.BaseUrl,
                ClientId = "test-client",            ClientSecret = "test-secret",
                Scope = "api.read",
                EnableAutoRefresh = true
            });
            services.AddSingleton<IAuthTokenStorage>(sharedTokenStorage);
            services.AddTransient<IAuthClient, AuthClient>();

            var serviceProvider = services.BuildServiceProvider();
            clients.Add(serviceProvider.GetRequiredService<IAuthClient>());
        }

        var stopwatch = Stopwatch.StartNew();
        var tasks = new List<Task<AuthToken>>();

        // Act - Each client makes multiple requests concurrently
        foreach (var client in clients)
        {
            for (int i = 0; i < 5; i++)
            {
                tasks.Add(client.AuthenticateClientCredentialsAsync());
            }
        }

        var results = await Task.WhenAll(tasks);
        stopwatch.Stop();

        // Assert
        results.Should().AllSatisfy(result =>
        {
            result.IsSuccess.Should().BeTrue();
            result.AccessToken.Should().NotBeNullOrEmpty();
        });

        var requestsPerSecond = results.Length / stopwatch.Elapsed.TotalSeconds;
        
        _output.WriteLine($"Shared Token Storage Performance:");
        _output.WriteLine($"Clients: {clients.Count}");
        _output.WriteLine($"Total Requests: {results.Length}");
        _output.WriteLine($"Duration: {stopwatch.Elapsed.TotalMilliseconds:F2} ms");
        _output.WriteLine($"Requests/Second: {requestsPerSecond:F2}");

        requestsPerSecond.Should().BeGreaterThan(15, "Shared token storage should not significantly impact throughput");
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _mockServer?.Dispose();
            _serviceProvider?.Dispose();
            _disposed = true;
        }
    }
}
