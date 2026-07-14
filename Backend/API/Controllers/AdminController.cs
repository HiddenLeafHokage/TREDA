using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Subscription;
using Application.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

/// <summary>
/// Admin operations guarded by a secret key (header <c>X-Admin-Key</c> must match the Admin:ApiKey
/// config / <c>Admin__ApiKey</c> env var). This is the test lever for granting subscriptions before
/// a real payment flow / admin dashboard exists.
/// </summary>
[ApiController]
[Route("api/admin")]
public class AdminController : ControllerBase
{
    private readonly ISubscriptionService _subscriptions;
    private readonly IConfiguration _configuration;

    public AdminController(ISubscriptionService subscriptions, IConfiguration configuration)
    {
        _subscriptions = subscriptions;
        _configuration = configuration;
    }

    /// <summary>Grant a vendor a subscription tier for a number of days (Free cancels it). Requires X-Admin-Key.</summary>
    [HttpPost("subscriptions")]
    public async Task<ActionResult<ApiResponse<SubscriptionStatusDto>>> SetSubscription([FromBody] SetSubscriptionDto dto)
    {
        var configuredKey = _configuration["Admin:ApiKey"];
        if (string.IsNullOrWhiteSpace(configuredKey))
            return StatusCode(503, ApiResponse<SubscriptionStatusDto>.ErrorResult(
                "Admin API is not enabled. Set the Admin__ApiKey environment variable.", ResponseCodes.SERVICE_UNAVAILABLE));

        var provided = Request.Headers["X-Admin-Key"].FirstOrDefault();
        if (string.IsNullOrEmpty(provided) || provided != configuredKey)
            return Unauthorized(ApiResponse<SubscriptionStatusDto>.ErrorResult("Invalid or missing admin key.", ResponseCodes.UNAUTHORIZED));

        var result = await _subscriptions.SetByEmailAsync(dto);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        if (result.Code == ResponseCodes.VALIDATION_ERROR) return BadRequest(result);
        return Ok(result);
    }
}
