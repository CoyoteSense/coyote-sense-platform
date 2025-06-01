using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Coyote.Infra.Security.Auth;

namespace CoyoteSense.OAuth2.Client.Tests.Integration;

/// <summary>
/// Test implementation of IAuthTokenStorage for integration tests
/// </summary>
public class InMemoryTokenStorage : IAuthTokenStorage
{
    private readonly Dictionary<string, AuthToken> _tokens = new();

    public Task StoreTokenAsync(string clientId, AuthToken token)
    {
        _tokens[clientId] = token;
        return Task.CompletedTask;
    }

    public AuthToken? GetToken(string clientId)
    {
        return _tokens.TryGetValue(clientId, out var token) ? token : null;
    }

    public void ClearToken(string clientId)
    {
        _tokens.Remove(clientId);
    }

    public void ClearAllTokens()
    {
        _tokens.Clear();
    }
}

/// <summary>
/// Test implementation of IAuthLogger for integration tests
/// </summary>
public class TestAuthLogger : IAuthLogger
{
    public void LogInfo(string message) => Console.WriteLine($"[INFO] {message}");
    public void LogError(string message) => Console.WriteLine($"[ERROR] {message}");
    public void LogDebug(string message) => Console.WriteLine($"[DEBUG] {message}");
}
