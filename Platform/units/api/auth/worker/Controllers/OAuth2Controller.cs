using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace CoyoteSense.AuthService.Controllers;

[ApiController]
[Route("/")]
public class OAuth2Controller : ControllerBase
{
    private readonly ILogger<OAuth2Controller> _logger;
    private readonly IOAuth2TokenService _tokenService;
    private readonly IOAuth2ClientService _clientService;
    private readonly IConfiguration _configuration;

    public OAuth2Controller(
        ILogger<OAuth2Controller> logger,
        IOAuth2TokenService tokenService,
        IOAuth2ClientService clientService,
        IConfiguration configuration)
    {
        _logger = logger;
        _tokenService = tokenService;
        _clientService = clientService;
        _configuration = configuration;
    }

    /// <summary>
    /// OAuth2 Token Endpoint - Supports Client Credentials, JWT Bearer, Authorization Code, and Refresh Token grants
    /// </summary>
    [HttpPost("token")]
    public async Task<IActionResult> Token([FromForm] OAuth2TokenRequest request)
    {
        try
        {
            _logger.LogInformation("Token request received: grant_type={GrantType}, client_id={ClientId}", 
                request.GrantType, request.ClientId);

            var tokenResponse = request.GrantType switch
            {
                "client_credentials" => await HandleClientCredentialsAsync(request),
                "urn:ietf:params:oauth:grant-type:jwt-bearer" => await HandleJwtBearerAsync(request),
                "authorization_code" => await HandleAuthorizationCodeAsync(request),
                "refresh_token" => await HandleRefreshTokenAsync(request),
                _ => throw new OAuth2Exception("unsupported_grant_type", "The authorization grant type is not supported")
            };

            _logger.LogInformation("Token issued successfully for client_id={ClientId}", request.ClientId);
            return Ok(tokenResponse);
        }
        catch (OAuth2Exception ex)
        {
            _logger.LogWarning("OAuth2 error: {Error} - {Description}", ex.Error, ex.ErrorDescription);
            return BadRequest(new OAuth2ErrorResponse
            {
                Error = ex.Error,
                ErrorDescription = ex.ErrorDescription
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token request");
            return BadRequest(new OAuth2ErrorResponse
            {
                Error = "server_error",
                ErrorDescription = "An unexpected error occurred"
            });
        }
    }

    /// <summary>
    /// OAuth2 Authorization Endpoint for interactive flows
    /// </summary>
    [HttpGet("authorize")]
    public async Task<IActionResult> Authorize([FromQuery] OAuth2AuthorizeRequest request)
    {
        try
        {
            // Validate client and redirect URI
            var client = await _clientService.GetClientAsync(request.ClientId);
            if (client == null)
            {
                return BadRequest("Invalid client_id");
            }

            if (!client.IsValidRedirectUri(request.RedirectUri))
            {
                return BadRequest("Invalid redirect_uri");
            }

            // For now, auto-approve (in production, this would show a consent screen)
            var authCode = await _tokenService.GenerateAuthorizationCodeAsync(request.ClientId, request.RedirectUri, request.Scope);

            var redirectUrl = $"{request.RedirectUri}?code={authCode}";
            if (!string.IsNullOrEmpty(request.State))
            {
                redirectUrl += $"&state={request.State}";
            }

            return Redirect(redirectUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during authorization");
            return BadRequest("Authorization failed");
        }
    }

    /// <summary>
    /// Token introspection endpoint for validation
    /// </summary>
    [HttpPost("introspect")]
    [Authorize]
    public async Task<IActionResult> Introspect([FromForm] OAuth2IntrospectRequest request)
    {
        try
        {
            var introspectionResult = await _tokenService.IntrospectTokenAsync(request.Token);
            return Ok(introspectionResult);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token introspection");
            return Ok(new OAuth2IntrospectResponse { Active = false });
        }
    }

    /// <summary>
    /// Token revocation endpoint
    /// </summary>
    [HttpPost("revoke")]
    public async Task<IActionResult> Revoke([FromForm] OAuth2RevokeRequest request)
    {
        try
        {
            await _tokenService.RevokeTokenAsync(request.Token);
            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token revocation");
            return BadRequest();
        }
    }

    // Grant type handlers

    private async Task<OAuth2TokenResponse> HandleClientCredentialsAsync(OAuth2TokenRequest request)
    {
        // Validate client credentials
        var client = await ValidateClientCredentialsAsync(request.ClientId, request.ClientSecret);
        
        // Generate access token
        var accessToken = await _tokenService.GenerateAccessTokenAsync(
            clientId: request.ClientId,
            scopes: ParseScopes(request.Scope),
            audience: "coyotesense-api"
        );

        return new OAuth2TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = int.Parse(_configuration["Auth:TokenTTL"] ?? "3600"),
            Scope = request.Scope
        };
    }

    private async Task<OAuth2TokenResponse> HandleJwtBearerAsync(OAuth2TokenRequest request)
    {
        // Validate JWT assertion
        var principal = await ValidateJwtAssertionAsync(request.Assertion);
        var clientId = principal.FindFirst("iss")?.Value ?? principal.FindFirst("sub")?.Value;

        if (string.IsNullOrEmpty(clientId))
        {
            throw new OAuth2Exception("invalid_grant", "Invalid JWT assertion");
        }

        // Generate access token
        var accessToken = await _tokenService.GenerateAccessTokenAsync(
            clientId: clientId,
            scopes: ParseScopes(request.Scope),
            audience: "coyotesense-api"
        );

        return new OAuth2TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = int.Parse(_configuration["Auth:TokenTTL"] ?? "3600"),
            Scope = request.Scope
        };
    }

    private async Task<OAuth2TokenResponse> HandleAuthorizationCodeAsync(OAuth2TokenRequest request)
    {
        // Validate authorization code
        var codeData = await _tokenService.ValidateAuthorizationCodeAsync(request.Code);
        
        // Generate tokens
        var accessToken = await _tokenService.GenerateAccessTokenAsync(
            clientId: codeData.ClientId,
            scopes: codeData.Scopes,
            audience: "coyotesense-api"
        );

        var refreshToken = await _tokenService.GenerateRefreshTokenAsync(codeData.ClientId);

        return new OAuth2TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = int.Parse(_configuration["Auth:TokenTTL"] ?? "3600"),
            RefreshToken = refreshToken,
            Scope = string.Join(" ", codeData.Scopes)
        };
    }

    private async Task<OAuth2TokenResponse> HandleRefreshTokenAsync(OAuth2TokenRequest request)
    {
        // Validate refresh token
        var refreshData = await _tokenService.ValidateRefreshTokenAsync(request.RefreshToken);
        
        // Generate new access token
        var accessToken = await _tokenService.GenerateAccessTokenAsync(
            clientId: refreshData.ClientId,
            scopes: refreshData.Scopes,
            audience: "coyotesense-api"
        );

        return new OAuth2TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = int.Parse(_configuration["Auth:TokenTTL"] ?? "3600"),
            Scope = string.Join(" ", refreshData.Scopes)
        };
    }

    // Helper methods

    private async Task<OAuth2Client> ValidateClientCredentialsAsync(string clientId, string clientSecret)
    {
        var client = await _clientService.GetClientAsync(clientId);
        if (client == null)
        {
            throw new OAuth2Exception("invalid_client", "Client authentication failed");
        }

        // Check mTLS if certificate is present
        if (HttpContext.Connection.ClientCertificate != null)
        {
            var isValidCert = await _clientService.ValidateClientCertificateAsync(clientId, HttpContext.Connection.ClientCertificate);
            if (!isValidCert)
            {
                throw new OAuth2Exception("invalid_client", "Client certificate validation failed");
            }
        }
        else if (!client.ValidateSecret(clientSecret))
        {
            throw new OAuth2Exception("invalid_client", "Client authentication failed");
        }

        return client;
    }

    private async Task<ClaimsPrincipal> ValidateJwtAssertionAsync(string assertion)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var jwt = tokenHandler.ReadJwtToken(assertion);
        
        // Get client public key for validation
        var clientId = jwt.Claims.FirstOrDefault(c => c.Type == "iss")?.Value;
        var client = await _clientService.GetClientAsync(clientId);
        
        if (client?.PublicKey == null)
        {
            throw new OAuth2Exception("invalid_grant", "Client public key not found");
        }

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = clientId,
            ValidateAudience = true,
            ValidAudience = _configuration["Auth:Issuer"] + "/token",
            ValidateLifetime = true,
            IssuerSigningKey = new RsaSecurityKey(client.PublicKey),
            ValidateIssuerSigningKey = true
        };

        var principal = tokenHandler.ValidateToken(assertion, validationParameters, out _);
        return principal;
    }

    private List<string> ParseScopes(string scope)
    {
        return string.IsNullOrEmpty(scope) 
            ? new List<string>() 
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
    }
}
