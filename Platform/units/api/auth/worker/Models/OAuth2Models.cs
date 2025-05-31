using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace CoyoteSense.AuthService;

// OAuth2 Request Models

public class OAuth2TokenRequest
{
    [JsonPropertyName("grant_type")]
    [Required]
    public string GrantType { get; set; } = string.Empty;

    [JsonPropertyName("client_id")]
    public string? ClientId { get; set; }

    [JsonPropertyName("client_secret")]
    public string? ClientSecret { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonPropertyName("assertion")]
    public string? Assertion { get; set; }

    [JsonPropertyName("code")]
    public string? Code { get; set; }

    [JsonPropertyName("redirect_uri")]
    public string? RedirectUri { get; set; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("code_verifier")]
    public string? CodeVerifier { get; set; }
}

public class OAuth2AuthorizeRequest
{
    [JsonPropertyName("response_type")]
    [Required]
    public string ResponseType { get; set; } = "code";

    [JsonPropertyName("client_id")]
    [Required]
    public string ClientId { get; set; } = string.Empty;

    [JsonPropertyName("redirect_uri")]
    [Required]
    public string RedirectUri { get; set; } = string.Empty;

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonPropertyName("state")]
    public string? State { get; set; }

    [JsonPropertyName("code_challenge")]
    public string? CodeChallenge { get; set; }

    [JsonPropertyName("code_challenge_method")]
    public string? CodeChallengeMethod { get; set; }
}

public class OAuth2IntrospectRequest
{
    [JsonPropertyName("token")]
    [Required]
    public string Token { get; set; } = string.Empty;

    [JsonPropertyName("token_type_hint")]
    public string? TokenTypeHint { get; set; }
}

public class OAuth2RevokeRequest
{
    [JsonPropertyName("token")]
    [Required]
    public string Token { get; set; } = string.Empty;

    [JsonPropertyName("token_type_hint")]
    public string? TokenTypeHint { get; set; }
}

// OAuth2 Response Models

public class OAuth2TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonPropertyName("id_token")]
    public string? IdToken { get; set; }
}

public class OAuth2ErrorResponse
{
    [JsonPropertyName("error")]
    public string Error { get; set; } = string.Empty;

    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; }

    [JsonPropertyName("error_uri")]
    public string? ErrorUri { get; set; }
}

public class OAuth2IntrospectResponse
{
    [JsonPropertyName("active")]
    public bool Active { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonPropertyName("client_id")]
    public string? ClientId { get; set; }

    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("token_type")]
    public string? TokenType { get; set; }

    [JsonPropertyName("exp")]
    public long? Exp { get; set; }

    [JsonPropertyName("iat")]
    public long? Iat { get; set; }

    [JsonPropertyName("sub")]
    public string? Sub { get; set; }

    [JsonPropertyName("aud")]
    public string? Aud { get; set; }

    [JsonPropertyName("iss")]
    public string? Iss { get; set; }

    [JsonPropertyName("jti")]
    public string? Jti { get; set; }
}

// Internal Data Models

public class AuthorizationCodeData
{
    public string ClientId { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public List<string> Scopes { get; set; } = new();
    public DateTime ExpiresAt { get; set; }
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
}

public class RefreshTokenData
{
    public string ClientId { get; set; } = string.Empty;
    public List<string> Scopes { get; set; } = new();
    public DateTime ExpiresAt { get; set; }
}

// OAuth2 Exception
public class OAuth2Exception : Exception
{
    public string Error { get; }
    public string? ErrorDescription { get; }
    public string? ErrorUri { get; }

    public OAuth2Exception(string error, string? errorDescription = null, string? errorUri = null)
        : base($"{error}: {errorDescription}")
    {
        Error = error;
        ErrorDescription = errorDescription;
        ErrorUri = errorUri;
    }
}
