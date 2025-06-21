using System;
using System.Collections.Generic;

namespace Coyote.Infra.Security.Auth.Options;

/// <summary>
/// Options for mutual TLS authentication
/// </summary>
public class MtlsOptions
{
    public string? ServerUrl { get; set; }
    public string? ClientId { get; set; }
    public string? ClientCertPath { get; set; }
    public string? ClientKeyPath { get; set; }
    public string? CaCertPath { get; set; }
    public List<string>? DefaultScopes { get; set; }
    public bool AutoRefresh { get; set; } = true;
    public int TimeoutMs { get; set; } = 30000;    public AuthClientConfig ToAuthClientConfig()
    {
        return new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentialsMtls,
            ServerUrl = ServerUrl ?? string.Empty,
            ClientId = ClientId ?? string.Empty,
            ClientCertPath = ClientCertPath ?? string.Empty,
            ClientKeyPath = ClientKeyPath ?? string.Empty,
            DefaultScopes = DefaultScopes ?? new List<string>(),
            AutoRefresh = AutoRefresh,
            TimeoutMs = TimeoutMs
        };
    }
}
