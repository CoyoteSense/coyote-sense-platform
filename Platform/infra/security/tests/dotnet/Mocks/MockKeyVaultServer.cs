using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;

namespace Coyote.Infra.Security.Tests.Mocks;

/// <summary>
/// Mock KeyVault server for integration testing
/// Provides realistic HTTP responses for KeyVault API endpoints
/// </summary>
public class MockKeyVaultServer : IDisposable
{
    private readonly IHost _host;
    private readonly Dictionary<string, MockSecret> _secrets;
    private readonly ILogger<MockKeyVaultServer> _logger;

    public string BaseUrl { get; }
    public int Port { get; }

    public MockKeyVaultServer(int port = 0)
    {
        _secrets = new Dictionary<string, MockSecret>();
        
        var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        _logger = loggerFactory.CreateLogger<MockKeyVaultServer>();

        // Create host with dynamic port allocation if port = 0
        var builder = Host.CreateDefaultBuilder()
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseUrls($"http://localhost:{(port == 0 ? "0" : port.ToString())}")
                         .Configure(ConfigureApp)
                         .ConfigureLogging(logging => logging.SetMinimumLevel(LogLevel.Warning));
            });

        _host = builder.Build();
        _host.Start();

        // Get the actual port assigned
        var server = _host.Services.GetService(typeof(IServer)) as Microsoft.AspNetCore.Hosting.Server.IServer;
        var addressFeature = server?.Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>();
        var address = addressFeature?.Addresses.FirstOrDefault();
        
        if (address != null && Uri.TryCreate(address, UriKind.Absolute, out var uri))
        {
            Port = uri.Port;
            BaseUrl = $"http://localhost:{Port}";
        }
        else
        {
            Port = port;
            BaseUrl = $"http://localhost:{Port}";
        }

        _logger.LogInformation("Mock KeyVault server started on {BaseUrl}", BaseUrl);
    }

    private void ConfigureApp(IApplicationBuilder app)
    {
        app.UseRouting();
        app.UseEndpoints(endpoints =>
        {            // Health endpoint
            endpoints.MapGet("/v1/health", HandleHealthAsync);
            
            // Secret metadata (must come before general secret operations)
            endpoints.MapGet("/v1/secret/{path}/metadata", HandleGetSecretMetadataAsync);
            
            // Secret operations
            endpoints.MapGet("/v1/secret/{*path}", HandleGetSecretAsync);
            endpoints.MapPost("/v1/secret/{*path}", HandleSetSecretAsync);
            endpoints.MapDelete("/v1/secret/{*path}", HandleDeleteSecretAsync);
            
            // List secrets
            endpoints.MapGet("/v1/secrets", HandleListSecretsAsync);
        });
    }

    public void AddSecret(string path, string value, Dictionary<string, string>? metadata = null)
    {
        _secrets[path] = new MockSecret
        {
            Path = path,
            Value = value,
            Version = "1",
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            Metadata = metadata ?? new Dictionary<string, string>(),
            Versions = new List<string> { "1" }
        };
        
        _logger.LogDebug("Added secret: {Path}", path);
    }

    public void RemoveSecret(string path)
    {
        _secrets.Remove(path);
        _logger.LogDebug("Removed secret: {Path}", path);
    }

    public void ClearSecrets()
    {
        _secrets.Clear();
        _logger.LogDebug("Cleared all secrets");
    }

    private async Task HandleHealthAsync(HttpContext context)
    {
        if (!IsAuthorized(context))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Unauthorized");
            return;
        }

        var health = new
        {
            status = "healthy",
            details = new Dictionary<string, object>
            {
                ["version"] = "1.0.0",
                ["uptime"] = "mock",
                ["secrets_count"] = _secrets.Count
            }
        };

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(health));
    }

    private async Task HandleGetSecretAsync(HttpContext context)
    {
        if (!IsAuthorized(context))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Unauthorized");
            return;
        }

        var path = context.Request.RouteValues["path"]?.ToString();
        if (string.IsNullOrEmpty(path))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Invalid path");
            return;
        }

        if (!_secrets.TryGetValue(path, out var secret))
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("Secret not found");
            return;
        }

        var response = new
        {
            data = new
            {
                value = secret.Value,
                version = secret.Version,
                created_at = secret.CreatedAt,
                updated_at = secret.UpdatedAt,
                metadata = secret.Metadata
            }
        };

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(response, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        }));
    }

    private async Task HandleSetSecretAsync(HttpContext context)
    {
        if (!IsAuthorized(context))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Unauthorized");
            return;
        }

        var path = context.Request.RouteValues["path"]?.ToString();
        if (string.IsNullOrEmpty(path))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Invalid path");
            return;
        }

        using var reader = new System.IO.StreamReader(context.Request.Body);
        var body = await reader.ReadToEndAsync();
        
        try
        {
            var request = JsonSerializer.Deserialize<SetSecretRequest>(body);
            if (request == null || string.IsNullOrEmpty(request.Value))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid request body");
                return;
            }

            var version = _secrets.ContainsKey(path) ? "2" : "1";
            var now = DateTime.UtcNow;

            _secrets[path] = new MockSecret
            {
                Path = path,
                Value = request.Value,
                Version = version,
                CreatedAt = _secrets.ContainsKey(path) ? _secrets[path].CreatedAt : now,
                UpdatedAt = now,
                Metadata = request.Metadata ?? new Dictionary<string, string>(),
                Versions = _secrets.ContainsKey(path) 
                    ? _secrets[path].Versions.Concat(new[] { version }).ToList()
                    : new List<string> { version }
            };

            var response = new { version };

            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(response));
        }
        catch (JsonException)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Invalid JSON");
        }
    }

    private async Task HandleDeleteSecretAsync(HttpContext context)
    {
        if (!IsAuthorized(context))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Unauthorized");
            return;
        }

        var path = context.Request.RouteValues["path"]?.ToString();
        if (string.IsNullOrEmpty(path))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Invalid path");
            return;
        }

        if (!_secrets.ContainsKey(path))
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("Secret not found");
            return;
        }

        _secrets.Remove(path);
        context.Response.StatusCode = 204; // No Content
    }

    private async Task HandleGetSecretMetadataAsync(HttpContext context)
    {
        if (!IsAuthorized(context))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Unauthorized");
            return;
        }

        var path = context.Request.RouteValues["path"]?.ToString();
        if (string.IsNullOrEmpty(path))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Invalid path");
            return;
        }

        if (!_secrets.TryGetValue(path, out var secret))
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("Secret not found");
            return;
        }

        var response = new
        {
            data = new
            {
                version = secret.Version,
                created_at = secret.CreatedAt,
                updated_at = secret.UpdatedAt,
                metadata = secret.Metadata,
                versions = secret.Versions
            }
        };

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(response, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        }));
    }

    private async Task HandleListSecretsAsync(HttpContext context)
    {
        if (!IsAuthorized(context))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Unauthorized");
            return;
        }

        var prefix = context.Request.Query["prefix"].ToString();
        var keys = string.IsNullOrEmpty(prefix) 
            ? _secrets.Keys.ToList()
            : _secrets.Keys.Where(k => k.StartsWith(prefix)).ToList();

        var response = new { keys };

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(response));
    }

    private static bool IsAuthorized(HttpContext context)
    {
        var authHeader = context.Request.Headers["Authorization"].ToString();
        
        // Accept any Bearer token for testing
        return authHeader.StartsWith("Bearer ") && authHeader.Length > 7;
    }

    public void Dispose()
    {
        _host?.StopAsync().Wait(TimeSpan.FromSeconds(5));
        _host?.Dispose();
        _logger.LogInformation("Mock KeyVault server stopped");
    }

    private class MockSecret
    {
        public string Path { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public Dictionary<string, string> Metadata { get; set; } = new();
        public List<string> Versions { get; set; } = new();
    }

    private class SetSecretRequest
    {
        public string Value { get; set; } = string.Empty;
        public Dictionary<string, string>? Metadata { get; set; }
    }
}

/// <summary>
/// Mock AuthClient for testing SecureStoreClient
/// </summary>
public class MockAuthClient : IAuthClient
{
    private string? _currentToken;
    private DateTime _tokenExpiry;
    private int _getTokenCallCount;

    public MockAuthClient(string? initialToken, DateTime expiry)
    {
        _currentToken = initialToken;
        _tokenExpiry = expiry;
    }

    public void UpdateToken(string token, DateTime expiry)
    {
        _currentToken = token;
        _tokenExpiry = expiry;
    }

    public int GetTokenCallCount => _getTokenCallCount;

    public Task<AuthResult> AuthenticateClientCredentialsAsync(List<string>? scopes = null, CancellationToken cancellationToken = default)
    {
        var result = new AuthResult
        {
            IsSuccess = !string.IsNullOrEmpty(_currentToken),
            Token = string.IsNullOrEmpty(_currentToken) ? null : new AuthToken
            {
                AccessToken = _currentToken,
                ExpiresAt = _tokenExpiry,
                Scopes = scopes ?? new List<string>()
            }
        };
        return Task.FromResult(result);
    }

    public Task<AuthToken?> GetValidTokenAsync(CancellationToken cancellationToken = default)
    {
        _getTokenCallCount++;
        
        if (string.IsNullOrEmpty(_currentToken) || DateTime.UtcNow >= _tokenExpiry)
        {
            return Task.FromResult<AuthToken?>(null);
        }

        return Task.FromResult<AuthToken?>(new AuthToken
        {
            AccessToken = _currentToken,
            ExpiresAt = _tokenExpiry,
            Scopes = new List<string> { "keyvault.read", "keyvault.write" }
        });
    }

    // Minimal implementations for interface compliance
    public AuthToken? CurrentToken => null;
    public bool IsAuthenticated => !string.IsNullOrEmpty(_currentToken) && DateTime.UtcNow < _tokenExpiry;

    public Task<AuthResult> AuthenticateJwtBearerAsync(string? subject = null, List<string>? scopes = null, CancellationToken cancellationToken = default)
        => throw new NotImplementedException();

    public Task<AuthResult> AuthenticateAuthorizationCodeAsync(string authorizationCode, string redirectUri, string? codeVerifier = null, CancellationToken cancellationToken = default)
        => throw new NotImplementedException();

    public (string authorizationUrl, string codeVerifier, string state) StartAuthorizationCodeFlow(string redirectUri, List<string>? scopes = null, string? state = null)
        => throw new NotImplementedException();

    public Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        => throw new NotImplementedException();

    public Task<bool> RevokeTokenAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
        => throw new NotImplementedException();

    public Task<bool> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
        => throw new NotImplementedException();

    public Task<bool> TestConnectionAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(true);

    public Task<AuthServerInfo?> GetServerInfoAsync(CancellationToken cancellationToken = default)
        => Task.FromResult<AuthServerInfo?>(null);

    public void ClearTokens() { }

    public void Dispose() { }
}
