using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Coyote.Infra.Security.Auth.Options;

/// <summary>
/// Options pattern for Client Credentials authentication
/// </summary>
public class ClientCredentialsOptions
{
    [Required]
    public string ServerUrl { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [Required]
    public string ClientSecret { get; set; } = string.Empty;

    public List<string> DefaultScopes { get; set; } = new();
    public int TimeoutMs { get; set; } = 30000;
    public bool AutoRefresh { get; set; } = true;
    public int RefreshBufferSeconds { get; set; } = 300;
    public int MaxRetryAttempts { get; set; } = 3;
    public int RetryDelayMs { get; set; } = 1000;
    public bool VerifySsl { get; set; } = true;
}

/// <summary>
/// Options pattern for mTLS authentication
/// </summary>
public class MtlsOptions
{
    [Required]
    public string ServerUrl { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [Required]
    public string ClientCertPath { get; set; } = string.Empty;

    [Required]
    public string ClientKeyPath { get; set; } = string.Empty;

    public string? CaCertPath { get; set; }

    public List<string> DefaultScopes { get; set; } = new();
    public int TimeoutMs { get; set; } = 30000;
    public bool AutoRefresh { get; set; } = true;
    public int RefreshBufferSeconds { get; set; } = 300;
    public int MaxRetryAttempts { get; set; } = 3;
    public int RetryDelayMs { get; set; } = 1000;
    public bool VerifySsl { get; set; } = true;
}

/// <summary>
/// Options pattern for JWT Bearer authentication
/// </summary>
public class JwtBearerOptions
{
    [Required]
    public string ServerUrl { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [Required]
    public string JwtSigningKeyPath { get; set; } = string.Empty;

    [Required]
    public string JwtIssuer { get; set; } = string.Empty;

    [Required]
    public string JwtAudience { get; set; } = string.Empty;

    public string JwtAlgorithm { get; set; } = "RS256";

    public List<string> DefaultScopes { get; set; } = new();
    public int TimeoutMs { get; set; } = 30000;
    public bool AutoRefresh { get; set; } = true;
    public int RefreshBufferSeconds { get; set; } = 300;
    public int MaxRetryAttempts { get; set; } = 3;
    public int RetryDelayMs { get; set; } = 1000;
    public bool VerifySsl { get; set; } = true;
}

/// <summary>
/// Options pattern for Authorization Code flow
/// </summary>
public class AuthorizationCodeOptions
{
    [Required]
    public string ServerUrl { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [Required]
    public string RedirectUri { get; set; } = string.Empty;

    public string? ClientSecret { get; set; }

    public bool UsePkce { get; set; } = true;

    public List<string> DefaultScopes { get; set; } = new();
    public int TimeoutMs { get; set; } = 30000;
    public bool AutoRefresh { get; set; } = true;
    public int RefreshBufferSeconds { get; set; } = 300;
    public int MaxRetryAttempts { get; set; } = 3;
    public int RetryDelayMs { get; set; } = 1000;
    public bool VerifySsl { get; set; } = true;
}

/// <summary>
/// Extension methods for converting options to AuthClientConfig
/// </summary>
public static class AuthOptionsExtensions
{
    public static AuthClientConfig ToAuthClientConfig(this ClientCredentialsOptions options)
    {
        return new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentials,
            ServerUrl = options.ServerUrl,
            ClientId = options.ClientId,
            ClientSecret = options.ClientSecret,
            DefaultScopes = options.DefaultScopes,
            TimeoutMs = options.TimeoutMs,
            AutoRefresh = options.AutoRefresh,
            RefreshBufferSeconds = options.RefreshBufferSeconds,
            MaxRetryAttempts = options.MaxRetryAttempts,
            RetryDelayMs = options.RetryDelayMs,
            VerifySsl = options.VerifySsl
        };
    }

    public static AuthClientConfig ToAuthClientConfig(this MtlsOptions options)
    {
        return new AuthClientConfig
        {
            AuthMode = AuthMode.ClientCredentialsMtls,
            ServerUrl = options.ServerUrl,
            ClientId = options.ClientId,
            ClientCertPath = options.ClientCertPath,
            ClientKeyPath = options.ClientKeyPath,
            CaCertPath = options.CaCertPath,
            DefaultScopes = options.DefaultScopes,
            TimeoutMs = options.TimeoutMs,
            AutoRefresh = options.AutoRefresh,
            RefreshBufferSeconds = options.RefreshBufferSeconds,
            MaxRetryAttempts = options.MaxRetryAttempts,
            RetryDelayMs = options.RetryDelayMs,
            VerifySsl = options.VerifySsl
        };
    }

    public static AuthClientConfig ToAuthClientConfig(this JwtBearerOptions options)
    {
        return new AuthClientConfig
        {
            AuthMode = AuthMode.JwtBearer,
            ServerUrl = options.ServerUrl,
            ClientId = options.ClientId,
            JwtSigningKeyPath = options.JwtSigningKeyPath,
            JwtIssuer = options.JwtIssuer,
            JwtAudience = options.JwtAudience,
            JwtAlgorithm = options.JwtAlgorithm,
            DefaultScopes = options.DefaultScopes,
            TimeoutMs = options.TimeoutMs,
            AutoRefresh = options.AutoRefresh,
            RefreshBufferSeconds = options.RefreshBufferSeconds,
            MaxRetryAttempts = options.MaxRetryAttempts,
            RetryDelayMs = options.RetryDelayMs,
            VerifySsl = options.VerifySsl
        };
    }

    public static AuthClientConfig ToAuthClientConfig(this AuthorizationCodeOptions options)
    {
        return new AuthClientConfig
        {
            AuthMode = options.UsePkce ? AuthMode.AuthorizationCodePkce : AuthMode.AuthorizationCode,
            ServerUrl = options.ServerUrl,
            ClientId = options.ClientId,
            ClientSecret = options.ClientSecret,
            RedirectUri = options.RedirectUri,
            UsePkce = options.UsePkce,
            DefaultScopes = options.DefaultScopes,
            TimeoutMs = options.TimeoutMs,
            AutoRefresh = options.AutoRefresh,
            RefreshBufferSeconds = options.RefreshBufferSeconds,
            MaxRetryAttempts = options.MaxRetryAttempts,
            RetryDelayMs = options.RetryDelayMs,
            VerifySsl = options.VerifySsl
        };
    }
}
