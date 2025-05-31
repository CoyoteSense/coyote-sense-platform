using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace CoyoteSense.AuthService;

// OAuth2 Token Service Interface
public interface IOAuth2TokenService
{
    Task<string> GenerateAccessTokenAsync(string clientId, List<string> scopes, string audience);
    Task<string> GenerateRefreshTokenAsync(string clientId);
    Task<string> GenerateAuthorizationCodeAsync(string clientId, string redirectUri, string? scope);
    Task<AuthorizationCodeData> ValidateAuthorizationCodeAsync(string code);
    Task<RefreshTokenData> ValidateRefreshTokenAsync(string refreshToken);
    Task<OAuth2IntrospectResponse> IntrospectTokenAsync(string token);
    Task<bool> RevokeTokenAsync(string token);
    Task<bool> IsTokenValidAsync(string token);
}

// JWT-based OAuth2 Token Service
public class JwtOAuth2TokenService : IOAuth2TokenService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<JwtOAuth2TokenService> _logger;
    private readonly Dictionary<string, AuthorizationCodeData> _authCodes = new();
    private readonly Dictionary<string, RefreshTokenData> _refreshTokens = new();
    private readonly HashSet<string> _revokedTokens = new();
    private readonly RSA _signingKey;

    public JwtOAuth2TokenService(IConfiguration configuration, ILogger<JwtOAuth2TokenService> logger)
    {
        _configuration = configuration;
        _logger = logger;
        _signingKey = LoadSigningKey();
    }

    private RSA LoadSigningKey()
    {
        var keyPath = _configuration["Auth:PrivateKeyPath"];
        if (!string.IsNullOrEmpty(keyPath) && File.Exists(keyPath))
        {
            var keyContent = File.ReadAllText(keyPath);
            var rsa = RSA.Create();
            rsa.ImportFromPem(keyContent);
            return rsa;
        }

        // Generate a key for development/testing
        _logger.LogWarning("No private key configured, generating temporary key for development");
        return RSA.Create(2048);
    }

    public Task<string> GenerateAccessTokenAsync(string clientId, List<string> scopes, string audience)
    {
        var issuer = _configuration["Auth:Issuer"] ?? "https://auth-service.coyotesense.local";
        var tokenTtl = int.Parse(_configuration["Auth:TokenTTL"] ?? "3600");

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, clientId),
            new(JwtRegisteredClaimNames.Iss, issuer),
            new(JwtRegisteredClaimNames.Aud, audience),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddSeconds(tokenTtl).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("client_id", clientId)
        };

        // Add scope claims
        foreach (var scope in scopes)
        {
            claims.Add(new Claim("scope", scope));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddSeconds(tokenTtl),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_signingKey), SecurityAlgorithms.RsaSha256)
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        _logger.LogInformation("Generated access token for client {ClientId} with scopes: {Scopes}", 
            clientId, string.Join(", ", scopes));

        return Task.FromResult(tokenString);
    }

    public Task<string> GenerateRefreshTokenAsync(string clientId)
    {
        var refreshToken = GenerateSecureToken();
        var refreshTtl = int.Parse(_configuration["Auth:RefreshTokenTTL"] ?? "86400");

        _refreshTokens[refreshToken] = new RefreshTokenData
        {
            ClientId = clientId,
            Scopes = new List<string>(), // Store scopes from original request
            ExpiresAt = DateTime.UtcNow.AddSeconds(refreshTtl)
        };

        _logger.LogInformation("Generated refresh token for client {ClientId}", clientId);
        return Task.FromResult(refreshToken);
    }

    public Task<string> GenerateAuthorizationCodeAsync(string clientId, string redirectUri, string? scope)
    {
        var authCode = GenerateSecureToken(16);
        var scopes = string.IsNullOrEmpty(scope) 
            ? new List<string>() 
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

        _authCodes[authCode] = new AuthorizationCodeData
        {
            ClientId = clientId,
            RedirectUri = redirectUri,
            Scopes = scopes,
            ExpiresAt = DateTime.UtcNow.AddMinutes(10) // Short TTL for auth codes
        };

        _logger.LogInformation("Generated authorization code for client {ClientId}", clientId);
        return Task.FromResult(authCode);
    }

    public Task<AuthorizationCodeData> ValidateAuthorizationCodeAsync(string code)
    {
        if (!_authCodes.TryGetValue(code, out var codeData))
        {
            throw new OAuth2Exception("invalid_grant", "Invalid authorization code");
        }

        if (DateTime.UtcNow > codeData.ExpiresAt)
        {
            _authCodes.Remove(code);
            throw new OAuth2Exception("invalid_grant", "Authorization code expired");
        }

        // Remove code after use (single use)
        _authCodes.Remove(code);

        _logger.LogInformation("Validated authorization code for client {ClientId}", codeData.ClientId);
        return Task.FromResult(codeData);
    }

    public Task<RefreshTokenData> ValidateRefreshTokenAsync(string refreshToken)
    {
        if (!_refreshTokens.TryGetValue(refreshToken, out var tokenData))
        {
            throw new OAuth2Exception("invalid_grant", "Invalid refresh token");
        }

        if (DateTime.UtcNow > tokenData.ExpiresAt)
        {
            _refreshTokens.Remove(refreshToken);
            throw new OAuth2Exception("invalid_grant", "Refresh token expired");
        }

        _logger.LogInformation("Validated refresh token for client {ClientId}", tokenData.ClientId);
        return Task.FromResult(tokenData);
    }

    public Task<OAuth2IntrospectResponse> IntrospectTokenAsync(string token)
    {
        try
        {
            if (_revokedTokens.Contains(token))
            {
                return Task.FromResult(new OAuth2IntrospectResponse { Active = false });
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var jwt = tokenHandler.ReadJwtToken(token);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _configuration["Auth:Issuer"],
                ValidateAudience = false, // Skip audience validation for introspection
                ValidateLifetime = true,
                IssuerSigningKey = new RsaSecurityKey(_signingKey),
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            tokenHandler.ValidateToken(token, validationParameters, out _);

            var response = new OAuth2IntrospectResponse
            {
                Active = true,
                ClientId = jwt.Claims.FirstOrDefault(c => c.Type == "client_id")?.Value,
                Sub = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value,
                Scope = string.Join(" ", jwt.Claims.Where(c => c.Type == "scope").Select(c => c.Value)),
                Exp = long.Parse(jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp)?.Value ?? "0"),
                Iat = long.Parse(jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Iat)?.Value ?? "0"),
                TokenType = "Bearer",
                Iss = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Iss)?.Value,
                Jti = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value
            };

            return Task.FromResult(response);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Token introspection failed");
            return Task.FromResult(new OAuth2IntrospectResponse { Active = false });
        }
    }

    public Task<bool> RevokeTokenAsync(string token)
    {
        _revokedTokens.Add(token);
        _logger.LogInformation("Token revoked: {TokenId}", GetTokenId(token));
        return Task.FromResult(true);
    }

    public Task<bool> IsTokenValidAsync(string token)
    {
        try
        {
            if (_revokedTokens.Contains(token))
            {
                return Task.FromResult(false);
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _configuration["Auth:Issuer"],
                ValidateAudience = false,
                ValidateLifetime = true,
                IssuerSigningKey = new RsaSecurityKey(_signingKey),
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            tokenHandler.ValidateToken(token, validationParameters, out _);
            return Task.FromResult(true);
        }
        catch
        {
            return Task.FromResult(false);
        }
    }

    private string GenerateSecureToken(int length = 32)
    {
        var bytes = new byte[length];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        return Convert.ToBase64String(bytes);
    }

    private string GetTokenId(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwt = tokenHandler.ReadJwtToken(token);
            return jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value ?? "unknown";
        }
        catch
        {
            return "unknown";
        }
    }
}
