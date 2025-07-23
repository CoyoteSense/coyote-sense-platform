using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Coyote.Units.KeyVault.Services;

namespace Coyote.Units.KeyVault.Controllers
{
    /// <summary>
    /// Authentication API controller
    /// </summary>
    [ApiController]
    [Route("v1/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// Authenticate a unit and receive a bearer token
        /// </summary>
        /// <param name="request">Authentication request</param>
        /// <returns>Bearer token</returns>
        [HttpPost]
        public async Task<ActionResult<AuthToken>> Authenticate([FromBody] UnitCredentials request)
        {
            try
            {
                var token = await _authService.AuthenticateAsync(request);
                return Ok(token);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Authentication failed for unit {UnitId}", request.UnitId);
                return Unauthorized(new { error = "Authentication failed" });
            }
        }

        /// <summary>
        /// Validate a bearer token
        /// </summary>
        /// <param name="token">Bearer token to validate</param>
        /// <returns>Validation result</returns>
        [HttpGet("validate")]
        [Authorize]
        public async Task<ActionResult<AuthValidationResult>> ValidateToken([FromQuery] string token)
        {
            try
            {
                var result = await _authService.ValidateTokenAsync(token);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token validation failed");
                return BadRequest(new { error = "Token validation failed" });
            }
        }

        /// <summary>
        /// Revoke a bearer token
        /// </summary>
        /// <param name="token">Token to revoke</param>
        /// <returns>Success status</returns>
        [HttpDelete("revoke")]
        [Authorize]
        public async Task<ActionResult> RevokeToken([FromQuery] string token)
        {
            try
            {
                var success = await _authService.RevokeTokenAsync(token);
                if (success)
                {
                    return Ok(new { message = "Token revoked successfully" });
                }
                return NotFound(new { error = "Token not found" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token revocation failed");
                return BadRequest(new { error = "Token revocation failed" });
            }
        }
    }
} 