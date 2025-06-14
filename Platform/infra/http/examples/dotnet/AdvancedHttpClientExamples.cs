using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Json;
using Coyote.Infra.Http;
using Coyote.Infra.Http.Factory;
using Coyote.Infra.Http.Modes.Recording;
using Coyote.Infra.Http.Modes.Replay;
using Coyote.Infra.Http.Modes.Simulation;

namespace Coyote.Infra.Http.Examples;

/// <summary>
/// Advanced examples demonstrating replay and simulation modes
/// </summary>
public class AdvancedHttpClientExamples
{
    /// <summary>
    /// Example of recording HTTP interactions and then replaying them
    /// </summary>
    public static async Task RecordAndReplayExample()
    {
        Console.WriteLine("=== Record and Replay Example ===");

        var tempRecordingPath = Path.Combine(Path.GetTempPath(), "http_recordings");
        Directory.CreateDirectory(tempRecordingPath);

        try
        {
            // Step 1: Record real HTTP interactions
            Console.WriteLine("Step 1: Recording HTTP interactions...");
            await RecordInteractions(tempRecordingPath);

            // Step 2: Replay recorded interactions
            Console.WriteLine("Step 2: Replaying recorded interactions...");
            await ReplayInteractions(tempRecordingPath);
        }
        finally
        {
            // Cleanup
            if (Directory.Exists(tempRecordingPath))
            {
                Directory.Delete(tempRecordingPath, true);
            }
        }
    }

    private static async Task RecordInteractions(string recordingPath)
    {
        // Configure services for recording mode
        var services = new ServiceCollection();
        
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Information));
        
        // Configure HTTP client with recording mode
        services.Configure<HttpClientOptions>(options =>
        {
            options.DefaultTimeoutMs = 5000;
            options.UserAgent = "Coyote-Recording-Example/1.0";
        });

        services.Configure<HttpClientModeOptions>(options =>
        {
            options.Mode = RuntimeMode.Recording;
            options.Recording = new RecordingModeOptions
            {
                RecordingPath = recordingPath,
                RecordBodies = true,
                RecordHeaders = true
            };
        });

        services.AddCoyoteHttpClient();

        var serviceProvider = services.BuildServiceProvider();
        var clientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();

        // Record some HTTP interactions (using mock for demo purposes)
        Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", "mock"); // Use mock for demo
        
        using var client = clientFactory.CreateClient();

        var requests = new[]
        {
            new { Url = "https://api.example.com/users", Method = HttpMethod.Get },
            new { Url = "https://api.example.com/users/123", Method = HttpMethod.Get },
            new { Url = "https://api.example.com/health", Method = HttpMethod.Get }
        };

        foreach (var req in requests)
        {
            var request = new HttpRequest
            {
                Url = req.Url,
                Method = req.Method,
                Headers = new Dictionary<string, string>
                {
                    ["Accept"] = "application/json",
                    ["X-API-Version"] = "v1"
                }
            };

            var response = await client.ExecuteAsync(request);
            Console.WriteLine($"Recorded: {req.Method} {req.Url} -> {response.StatusCode}");
        }

        Console.WriteLine($"Recordings saved to: {recordingPath}");
        
        // List recorded files
        var files = Directory.GetFiles(recordingPath, "*.json");
        Console.WriteLine($"Total recordings: {files.Length}");
    }

    private static async Task ReplayInteractions(string recordingPath)
    {
        // Configure services for replay mode
        var services = new ServiceCollection();
        
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Information));
        
        services.Configure<HttpClientOptions>(options =>
        {
            options.DefaultTimeoutMs = 5000;
        });

        services.Configure<HttpClientModeOptions>(options =>
        {
            options.Mode = RuntimeMode.Replay;
            options.Replay = new ReplayModeOptions
            {
                RecordingPath = recordingPath,
                SequentialMode = false,
                LoopRecordings = false,
                FallbackMode = ReplayFallbackMode.DefaultResponse
            };
        });

        services.AddCoyoteHttpClient();

        var serviceProvider = services.BuildServiceProvider();
        var clientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();

        using var client = clientFactory.CreateClient();
        
        // Make requests that should match recorded interactions
        var testRequests = new[]
        {
            "https://api.example.com/users",
            "https://api.example.com/users/123", 
            "https://api.example.com/health",
            "https://api.example.com/notrecorded" // This should fallback
        };

        foreach (var url in testRequests)
        {
            var request = new HttpRequest
            {
                Url = url,
                Method = HttpMethod.Get
            };

            var response = await client.ExecuteAsync(request);
            Console.WriteLine($"Replayed: GET {url} -> {response.StatusCode}");
            
            if (!string.IsNullOrEmpty(response.Body))
            {
                Console.WriteLine($"  Body: {response.Body.Substring(0, Math.Min(100, response.Body.Length))}...");
            }
        }

        // Get replay statistics
        if (client is ReplayHttpClient replayClient)
        {
            var stats = replayClient.GetStats();
            Console.WriteLine($"Replay Stats: {stats.TotalRecordings} total, {stats.RemainingResponses} remaining");
        }
    }

    /// <summary>
    /// Example of using simulation mode with custom scenarios
    /// </summary>
    public static async Task SimulationExample()
    {
        Console.WriteLine("\n=== Simulation Example ===");

        var tempScenarioPath = Path.Combine(Path.GetTempPath(), "simulation_scenarios.json");

        try
        {
            // Create custom simulation scenarios
            await CreateSimulationScenarios(tempScenarioPath);

            // Run simulation
            await RunSimulation(tempScenarioPath);
        }
        finally
        {
            if (File.Exists(tempScenarioPath))
            {
                File.Delete(tempScenarioPath);
            }
        }
    }

    private static async Task CreateSimulationScenarios(string scenarioPath)
    {
        var scenarios = new[]
        {
            new SimulationScenario
            {
                Name = "User Service - Fast",
                Pattern = "/api/users/*",
                StatusCode = 200,
                Body = "{\"users\": [{\"id\": \"{{timestamp}}\", \"name\": \"Test User\"}]}",
                Headers = new Dictionary<string, string>
                {
                    ["Content-Type"] = "application/json",
                    ["X-Response-Time"] = "fast"
                },
                MinLatencyMs = 10,
                MaxLatencyMs = 50
            },
            new SimulationScenario
            {
                Name = "Payment Service - Slow",
                Pattern = "/api/payments/*",
                StatusCode = 200,
                Body = "{\"transaction\": \"{{timestamp}}\", \"status\": \"processing\"}",
                Headers = new Dictionary<string, string>
                {
                    ["Content-Type"] = "application/json",
                    ["X-Processing-Time"] = "slow"
                },
                MinLatencyMs = 1000,
                MaxLatencyMs = 3000
            },
            new SimulationScenario
            {
                Name = "External API - Unreliable",
                Pattern = "/external/*",
                StatusCode = 503,
                Body = "{\"error\": \"Service temporarily unavailable\"}",
                Headers = new Dictionary<string, string>
                {
                    ["Content-Type"] = "application/json",
                    ["Retry-After"] = "60"
                },
                FailureRate = 0.7, // 70% failure rate
                FailureMessages = new List<string>
                {
                    "Connection timeout",
                    "Service overloaded",
                    "Rate limit exceeded"
                }
            },
            new SimulationScenario
            {
                Name = "Auth Service - Secure",
                Pattern = "/auth/*",
                StatusCode = 401,
                Body = "{\"error\": \"Unauthorized\", \"message\": \"Invalid or expired token\"}",
                Headers = new Dictionary<string, string>
                {
                    ["Content-Type"] = "application/json",
                    ["WWW-Authenticate"] = "Bearer"
                },
                MinLatencyMs = 100,
                MaxLatencyMs = 200
            }
        };

        var json = JsonSerializer.Serialize(scenarios, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(scenarioPath, json);
        
        Console.WriteLine($"Created simulation scenarios: {scenarioPath}");
    }

    private static async Task RunSimulation(string scenarioPath)
    {
        // Configure services for simulation mode
        var services = new ServiceCollection();
        
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Information));
        
        services.Configure<HttpClientOptions>(options =>
        {
            options.DefaultTimeoutMs = 10000; // Higher timeout for slow simulations
        });

        services.Configure<HttpClientModeOptions>(options =>
        {
            options.Mode = RuntimeMode.Simulation;
            options.Simulation = new SimulationModeOptions
            {
                ScenarioPath = scenarioPath,
                GlobalLatencyMs = 50, // Add 0-50ms to all requests
                GlobalFailureRate = 0.05, // 5% global failure rate
                MinPingLatencyMs = 10,
                MaxPingLatencyMs = 100,
                PingFailureRate = 0.1 // 10% ping failure rate
            };
        });

        services.AddCoyoteHttpClient();

        var serviceProvider = services.BuildServiceProvider();
        var clientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();

        using var client = clientFactory.CreateClient();

        // Test different scenarios
        var testCases = new[]
        {
            new { Url = "https://api.example.com/api/users/123", Description = "Fast User Service" },
            new { Url = "https://api.example.com/api/payments/456", Description = "Slow Payment Service" },
            new { Url = "https://api.example.com/external/service", Description = "Unreliable External API" },
            new { Url = "https://api.example.com/auth/validate", Description = "Secure Auth Service" },
            new { Url = "https://api.example.com/unknown/endpoint", Description = "Default Scenario" }
        };

        foreach (var testCase in testCases)
        {
            Console.WriteLine($"\nTesting: {testCase.Description}");
            
            var startTime = DateTime.UtcNow;
            
            try
            {
                var request = new HttpRequest
                {
                    Url = testCase.Url,
                    Method = HttpMethod.Get,
                    Headers = new Dictionary<string, string>
                    {
                        ["Authorization"] = "Bearer test-token",
                        ["Accept"] = "application/json"
                    }
                };

                var response = await client.ExecuteAsync(request);
                var duration = DateTime.UtcNow - startTime;

                Console.WriteLine($"  URL: {testCase.Url}");
                Console.WriteLine($"  Status: {response.StatusCode}");
                Console.WriteLine($"  Duration: {duration.TotalMilliseconds:F0}ms");
                
                if (!string.IsNullOrEmpty(response.ErrorMessage))
                {
                    Console.WriteLine($"  Error: {response.ErrorMessage}");
                }
                else if (!string.IsNullOrEmpty(response.Body))
                {
                    var bodyPreview = response.Body.Length > 100 
                        ? response.Body.Substring(0, 100) + "..." 
                        : response.Body;
                    Console.WriteLine($"  Body: {bodyPreview}");
                }

                // Show custom headers
                foreach (var header in response.Headers.Where(h => h.Key.StartsWith("X-")))
                {
                    Console.WriteLine($"  {header.Key}: {header.Value}");
                }
            }
            catch (Exception ex)
            {
                var duration = DateTime.UtcNow - startTime;
                Console.WriteLine($"  Exception after {duration.TotalMilliseconds:F0}ms: {ex.Message}");
            }
        }

        // Test ping functionality
        Console.WriteLine("\nTesting ping functionality:");
        var pingTargets = new[] 
        { 
            "https://api.example.com/health",
            "https://external.service.com/status"
        };

        foreach (var target in pingTargets)
        {
            var pingStart = DateTime.UtcNow;
            var pingResult = await client.PingAsync(target);
            var pingDuration = DateTime.UtcNow - pingStart;
            
            Console.WriteLine($"  Ping {target}: {(pingResult ? "Success" : "Failed")} ({pingDuration.TotalMilliseconds:F0}ms)");
        }

        // Get simulation statistics
        if (client is SimulationHttpClient simClient)
        {
            var stats = simClient.GetStats();
            Console.WriteLine($"\nSimulation Stats:");
            Console.WriteLine($"  Total scenarios: {stats.TotalScenarios}");
            Console.WriteLine($"  Custom scenarios: {stats.CustomScenarios}");
            Console.WriteLine($"  Default scenarios: {stats.DefaultScenarios}");
        }
    }

    /// <summary>
    /// Example demonstrating runtime mode switching
    /// </summary>
    public static async Task RuntimeModeSwitchingExample()
    {
        Console.WriteLine("\n=== Runtime Mode Switching Example ===");

        var modes = new[] 
        { 
            RuntimeMode.Testing,     // Mock mode
            RuntimeMode.Debug,       // Debug wrapper around real client
            RuntimeMode.Simulation   // Simulation mode
        };

        foreach (var mode in modes)
        {
            Console.WriteLine($"\nTesting mode: {mode}");
            
            // Set environment variable to control mode
            Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", mode.ToString().ToLower());

            var services = new ServiceCollection();
            services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Warning));
            services.AddCoyoteHttpClient();

            var serviceProvider = services.BuildServiceProvider();
            var clientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();

            using var client = clientFactory.CreateClient();

            var request = new HttpRequest
            {
                Url = "https://api.example.com/test",
                Method = HttpMethod.Get
            };

            var startTime = DateTime.UtcNow;
            var response = await client.ExecuteAsync(request);
            var duration = DateTime.UtcNow - startTime;

            Console.WriteLine($"  Status: {response.StatusCode}");
            Console.WriteLine($"  Duration: {duration.TotalMilliseconds:F0}ms");
            Console.WriteLine($"  Body preview: {(response.Body?.Length > 50 ? response.Body.Substring(0, 50) + "..." : response.Body)}");
        }

        // Clear environment variable
        Environment.SetEnvironmentVariable("COYOTE_RUNTIME_MODE", null);
    }

    /// <summary>
    /// Example of advanced testing with HTTP client modes
    /// </summary>
    public static async Task AdvancedTestingExample()
    {
        Console.WriteLine("\n=== Advanced Testing Example ===");

        // This example shows how to use different modes for comprehensive testing
        
        // 1. Unit testing with mock client
        Console.WriteLine("1. Unit Testing with Mock Client");
        await TestWithMockClient();

        // 2. Integration testing with recording/replay
        Console.WriteLine("\n2. Integration Testing with Record/Replay");
        var recordingPath = await RecordRealInteractions();
        await TestWithReplayClient(recordingPath);

        // 3. Load testing with simulation
        Console.WriteLine("\n3. Load Testing with Simulation");
        await TestWithSimulationClient();

        // Cleanup
        if (Directory.Exists(recordingPath))
        {
            Directory.Delete(recordingPath, true);
        }
    }

    private static async Task TestWithMockClient()
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Warning));
        
        services.Configure<HttpClientModeOptions>(options =>
        {
            options.Mode = RuntimeMode.Testing;
            options.Mock.DefaultStatusCode = 200;
            options.Mock.DefaultBody = "{\"success\": true, \"data\": \"mock response\"}";
            options.Mock.DelayMs = 10; // Fast for unit tests
        });

        services.AddCoyoteHttpClient();
        var serviceProvider = services.BuildServiceProvider();
        var clientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();

        using var client = clientFactory.CreateClient();

        // Test various scenarios quickly
        var scenarios = new[]
        {
            "https://api.service.com/users",
            "https://api.service.com/orders", 
            "https://api.service.com/products"
        };

        foreach (var url in scenarios)
        {
            var response = await client.ExecuteAsync(new HttpRequest { Url = url, Method = HttpMethod.Get });
            Console.WriteLine($"  Mock test: {url} -> {response.StatusCode}");
        }
    }

    private static async Task<string> RecordRealInteractions()
    {
        var recordingPath = Path.Combine(Path.GetTempPath(), $"integration_recordings_{Guid.NewGuid():N}");
        Directory.CreateDirectory(recordingPath);

        // This would typically record against real services
        // For demo, we'll create some mock recordings
        var mockRecordings = new[]
        {
            new { Url = "https://api.service.com/users", Status = 200, Body = "{\"users\": []}" },
            new { Url = "https://api.service.com/orders", Status = 200, Body = "{\"orders\": []}" }
        };

        foreach (var mock in mockRecordings)
        {
            var recording = new
            {
                Timestamp = DateTime.UtcNow,
                Request = new { Url = mock.Url, Method = "GET", Headers = (object?)null, Body = (string?)null },
                Response = new { StatusCode = mock.Status, Headers = (object?)null, Body = mock.Body, ErrorMessage = (string?)null }
            };

            var json = JsonSerializer.Serialize(recording, new JsonSerializerOptions { WriteIndented = true });
            var fileName = $"recording_{Guid.NewGuid():N}.json";
            await File.WriteAllTextAsync(Path.Combine(recordingPath, fileName), json);
        }

        Console.WriteLine($"  Created mock recordings in: {recordingPath}");
        return recordingPath;
    }

    private static async Task TestWithReplayClient(string recordingPath)
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Warning));
        
        services.Configure<HttpClientModeOptions>(options =>
        {
            options.Mode = RuntimeMode.Replay;
            options.Replay.RecordingPath = recordingPath;
            options.Replay.SequentialMode = false;
        });

        services.AddCoyoteHttpClient();
        var serviceProvider = services.BuildServiceProvider();
        var clientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();

        using var client = clientFactory.CreateClient();

        // Test with recorded interactions
        var testUrls = new[]
        {
            "https://api.service.com/users",
            "https://api.service.com/orders",
            "https://api.service.com/notrecorded" // Should fallback
        };

        foreach (var url in testUrls)
        {
            var response = await client.ExecuteAsync(new HttpRequest { Url = url, Method = HttpMethod.Get });
            Console.WriteLine($"  Replay test: {url} -> {response.StatusCode}");
        }
    }

    private static async Task TestWithSimulationClient()
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Warning));
        
        services.Configure<HttpClientModeOptions>(options =>
        {
            options.Mode = RuntimeMode.Simulation;
            options.Simulation.GlobalLatencyMs = 200; // Simulate network conditions
            options.Simulation.GlobalFailureRate = 0.1; // 10% failure rate
        });

        services.AddCoyoteHttpClient();
        var serviceProvider = services.BuildServiceProvider();
        var clientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();

        using var client = clientFactory.CreateClient();

        // Simulate load testing scenarios
        var tasks = new List<Task>();
        
        for (int i = 0; i < 10; i++)
        {
            tasks.Add(Task.Run(async () =>
            {
                var response = await client.ExecuteAsync(new HttpRequest 
                { 
                    Url = $"https://api.service.com/load-test/{i}", 
                    Method = HttpMethod.Get 
                });
                Console.WriteLine($"  Load test {i}: {response.StatusCode}");
            }));
        }

        await Task.WhenAll(tasks);
    }
}
