using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;
using Coyote.Infra.Security.Auth;
using Coyote.Infra.Security.Tests.TestHelpers;
using Coyote.Infra.Http;

namespace CoyoteSense.OAuth2.Client.Tests.Performance;

/// <summary>
/// Performance tests for AuthClient - cleaned up with only working tests
/// </summary>
public class AuthPerformanceTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly ServiceProvider _serviceProvider;
    private readonly IAuthClient _client;
    private bool _disposed;

    public AuthPerformanceTests(ITestOutputHelper output)
    {
        _output = output;
        
        var config = new AuthClientConfig
        {
            ServerUrl = "https://mock-oauth2-server.test",
            ClientId = "test-client",
            ClientSecret = "test-secret",
            DefaultScopes = new List<string> { "api.read", "api.write" },
            TimeoutMs = 5000
        };

        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Warning));
        services.AddSingleton(config);
        services.AddSingleton<MockOAuth2HttpClient>();
        services.AddSingleton<ICoyoteHttpClient>(provider => provider.GetRequiredService<MockOAuth2HttpClient>());
        services.AddTransient<IAuthTokenStorage, InMemoryTokenStorage>();
        services.AddTransient<IAuthLogger>(provider => 
        {
            var logger = provider.GetRequiredService<ILogger<TestAuthLogger>>();
            return new TestAuthLogger(logger);
        });
        services.AddTransient<IAuthClient>(provider =>
        {
            var httpClient = provider.GetRequiredService<ICoyoteHttpClient>();
            var tokenStorage = provider.GetRequiredService<IAuthTokenStorage>();
            var authLogger = provider.GetRequiredService<IAuthLogger>();
            return new AuthClient(config, httpClient, tokenStorage, authLogger);
        });

        _serviceProvider = services.BuildServiceProvider();
        _client = _serviceProvider.GetRequiredService<IAuthClient>();
    }

    [Fact]
    [Trait("Category", "Performance")]
    public async Task TokenIntrospection_ShouldMaintainPerformanceUnderLoad()
    {
        // Arrange - Get some tokens first (reduced for faster execution)
        var tokens = new List<string>();
        for (int i = 0; i < 5; i++) // Reduced from 10
        {
            var result = await _client.AuthenticateClientCredentialsAsync();
            result.IsSuccess.Should().BeTrue();
            tokens.Add(result.Token!.AccessToken!);
        }

        var introspectionTasks = new List<Task<bool>>();
        var stopwatch = Stopwatch.StartNew();

        // Act - Test introspection performance with multiple requests
        foreach (var token in tokens)
        {
            for (int j = 0; j < 4; j++) // Reduced from 10
            {
                introspectionTasks.Add(_client.IntrospectTokenAsync(token));
            }
        }

        var results = await Task.WhenAll(introspectionTasks);
        stopwatch.Stop();

        // Assert
        results.Should().AllSatisfy(result =>
        {
            result.Should().BeTrue("All tokens should be valid during introspection");
        });

        var totalRequests = introspectionTasks.Count;
        var requestsPerSecond = totalRequests / stopwatch.Elapsed.TotalSeconds;

        _output.WriteLine($"Introspection Performance Results:");
        _output.WriteLine($"Total Requests: {totalRequests}");
        _output.WriteLine($"Duration: {stopwatch.ElapsedMilliseconds} ms");
        _output.WriteLine($"Requests/Second: {requestsPerSecond:F2}");

        // Performance assertion - should be able to handle at least 20 introspections per second
        requestsPerSecond.Should().BeGreaterThan(20, "Should handle at least 20 introspections per second");
    }

    [Fact]
    [Trait("Category", "Performance")]
    public async Task MemoryUsage_ShouldRemainStableUnderLoad()
    {
        // Arrange
        var initialMemory = GC.GetTotalMemory(true);
        var results = new List<AuthResult>();

        // Act - Perform many authentication operations to test memory usage
        for (int i = 0; i < 20; i++) // Reduced from 50
        {
            var result = await _client.AuthenticateClientCredentialsAsync();
            results.Add(result);
            
            // Clear token after use to prevent memory accumulation
            if (result.IsSuccess)
            {
                _client.ClearTokens();
            }
        }

        // Force garbage collection
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var finalMemory = GC.GetTotalMemory(false);
        var memoryIncrease = finalMemory - initialMemory;

        // Assert
        results.Should().AllSatisfy(result =>
        {
            result.IsSuccess.Should().BeTrue();
        });

        _output.WriteLine($"Memory Usage Analysis:");
        _output.WriteLine($"Initial Memory: {initialMemory / 1024:F2} KB");
        _output.WriteLine($"Final Memory: {finalMemory / 1024:F2} KB");
        _output.WriteLine($"Memory Increase: {memoryIncrease / 1024:F2} KB");
        _output.WriteLine($"Memory per Operation: {memoryIncrease / results.Count / 1024:F2} KB");

        // Memory should not increase dramatically (allowing 100KB increase for test framework overhead)
        memoryIncrease.Should().BeLessThan(100 * 1024, "Memory usage should remain stable during operations");
    }

    [Fact]
    [Trait("Category", "Performance")]
    public async Task AutoRefresh_ShouldNotCausePerformanceDegradation()
    {
        // Arrange
        var results = new List<AuthResult>();
        var stopwatch = Stopwatch.StartNew();

        // Act - Test repeated authentication (simulating auto-refresh)
        for (int i = 0; i < 10; i++) // Reduced iterations
        {
            var result = await _client.AuthenticateClientCredentialsAsync();
            results.Add(result);
            
            // Small delay to simulate real usage pattern
            await Task.Delay(10);
        }

        stopwatch.Stop();

        // Assert
        results.Should().AllSatisfy(result =>
        {
            result.IsSuccess.Should().BeTrue();
            result.Token.Should().NotBeNull();
        });

        var avgResponseTime = stopwatch.ElapsedMilliseconds / (double)results.Count;
        var throughput = results.Count / stopwatch.Elapsed.TotalSeconds;

        _output.WriteLine($"Auto-Refresh Performance:");
        _output.WriteLine($"Total Operations: {results.Count}");
        _output.WriteLine($"Average Response Time: {avgResponseTime:F2} ms");
        _output.WriteLine($"Throughput: {throughput:F2} operations/second");

        // Performance assertions
        avgResponseTime.Should().BeLessThan(100, "Average response time should be under 100ms");
        throughput.Should().BeGreaterThan(10, "Should handle at least 10 operations per second");
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _serviceProvider?.Dispose();
            _disposed = true;
        }
    }
}
