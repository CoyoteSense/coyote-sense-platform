using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Coyote.Units.KeyVault.Services;

namespace Coyote.Units.KeyVault.Controllers
{
    /// <summary>
    /// Secrets API controller
    /// </summary>
    [ApiController]
    [Route("v1/secret")]
    [Authorize]
    public class SecretsController : ControllerBase
    {
        private readonly ISecretService _secretService;
        private readonly ILogger<SecretsController> _logger;

        public SecretsController(ISecretService secretService, ILogger<SecretsController> logger)
        {
            _secretService = secretService;
            _logger = logger;
        }

        /// <summary>
        /// Get a secret by path
        /// </summary>
        /// <param name="path">Secret path</param>
        /// <returns>Secret value</returns>
        [HttpGet("{*path}")]
        public async Task<ActionResult<string>> GetSecret(string path)
        {
            try
            {
                // Extract unit ID from authorization context
                var unitId = User.Identity?.Name ?? "unknown";
                
                var secret = await _secretService.GetSecretAsync(path, unitId);
                return Ok(new { value = secret });
            }
            catch (KeyNotFoundException)
            {
                return NotFound(new { error = $"Secret not found: {path}" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve secret {Path}", path);
                return BadRequest(new { error = "Failed to retrieve secret" });
            }
        }

        /// <summary>
        /// Set a secret at the specified path
        /// </summary>
        /// <param name="path">Secret path</param>
        /// <param name="request">Secret value</param>
        /// <returns>Success status</returns>
        [HttpPost("{*path}")]
        public async Task<ActionResult> SetSecret(string path, [FromBody] SetSecretRequest request)
        {
            try
            {
                var unitId = User.Identity?.Name ?? "unknown";
                
                var success = await _secretService.SetSecretAsync(path, request.Value, unitId);
                if (success)
                {
                    return Ok(new { message = "Secret stored successfully" });
                }
                return BadRequest(new { error = "Failed to store secret" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to store secret {Path}", path);
                return BadRequest(new { error = "Failed to store secret" });
            }
        }

        /// <summary>
        /// Delete a secret
        /// </summary>
        /// <param name="path">Secret path</param>
        /// <returns>Success status</returns>
        [HttpDelete("{*path}")]
        public async Task<ActionResult> DeleteSecret(string path)
        {
            try
            {
                var unitId = User.Identity?.Name ?? "unknown";
                
                var success = await _secretService.DeleteSecretAsync(path, unitId);
                if (success)
                {
                    return Ok(new { message = "Secret deleted successfully" });
                }
                return NotFound(new { error = $"Secret not found: {path}" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete secret {Path}", path);
                return BadRequest(new { error = "Failed to delete secret" });
            }
        }

        /// <summary>
        /// List all secrets for the current unit
        /// </summary>
        /// <returns>List of secret paths</returns>
        [HttpGet("list")]
        public async Task<ActionResult<string[]>> ListSecrets()
        {
            try
            {
                var unitId = User.Identity?.Name ?? "unknown";
                
                var secrets = await _secretService.ListSecretsAsync(unitId);
                return Ok(new { secrets });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to list secrets");
                return BadRequest(new { error = "Failed to list secrets" });
            }
        }
    }

    /// <summary>
    /// Request model for setting secrets
    /// </summary>
    public class SetSecretRequest
    {
        public string Value { get; set; } = string.Empty;
    }
} 