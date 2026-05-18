using API.Attributes;
using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Notification;
using Application.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace API.Controllers;

/// <summary>Vendor notification center (bell + notifications page).</summary>
[ApiController]
[Route("api/vendor/notifications")]
[SimpleAuthorize(AppConstants.Roles.Vendor, AppConstants.Roles.Admin)]
public class VendorNotificationsController : ControllerBase
{
    private readonly IVendorNotificationService _notifications;

    public VendorNotificationsController(IVendorNotificationService notifications)
    {
        _notifications = notifications;
    }

    private string? VendorId => User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    /// <summary>List notifications. category: all | Order | Payment | Message | Promotion</summary>
    [HttpGet]
    public async Task<ActionResult<ApiResponse<PagedListDto<VendorNotificationDto>>>> GetList(
        [FromQuery] string? category = "all",
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<PagedListDto<VendorNotificationDto>>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _notifications.GetPagedAsync(VendorId, category, page, pageSize);
        return Ok(result);
    }

    [HttpGet("summary")]
    public async Task<ActionResult<ApiResponse<NotificationSummaryDto>>> GetSummary()
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<NotificationSummaryDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _notifications.GetSummaryAsync(VendorId);
        return Ok(result);
    }

    [HttpPut("{notificationId}/read")]
    public async Task<ActionResult<ApiResponse<bool>>> MarkRead(string notificationId)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<bool>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _notifications.MarkReadAsync(VendorId, notificationId);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        return Ok(result);
    }

    /// <summary>Mark all as read. Optional category filter (same values as list).</summary>
    [HttpPut("read-all")]
    public async Task<ActionResult<ApiResponse<bool>>> MarkAllRead([FromQuery] string? category = null)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<bool>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _notifications.MarkAllReadAsync(VendorId, category);
        return Ok(result);
    }
}
