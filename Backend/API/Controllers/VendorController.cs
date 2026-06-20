using API.Attributes;
using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Order;
using Application.DTOs.Product;
using Application.DTOs.Vendor;
using Application.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
[SimpleAuthorize(AppConstants.Roles.Vendor, AppConstants.Roles.Admin)]
public class VendorController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly IProductService _productService;
    private readonly IOrderService _orderService;
    private readonly ILogger<VendorController> _logger;

    public VendorController(IAuthService authService, IProductService productService, IOrderService orderService, ILogger<VendorController> logger)
    {
        _authService = authService;
        _productService = productService;
        _orderService = orderService;
        _logger = logger;
    }

    private string? VendorId => User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    [HttpGet("profile")]
    public async Task<ActionResult<ApiResponse<VendorProfileDto>>> GetProfile()
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<VendorProfileDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));

        var result = await _authService.GetVendorProfileAsync(VendorId);
        if (result.Code == ResponseCodes.NOT_FOUND)
            return NotFound(result);
        return Ok(result);
    }

    [HttpPut("profile")]
    public async Task<ActionResult<ApiResponse<bool>>> UpdateProfile([FromBody] UpdateVendorProfileDto dto)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<bool>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));

        var result = await _authService.UpdateVendorProfileAsync(VendorId, dto);
        if (result.Code == ResponseCodes.NOT_FOUND)
            return NotFound(result);
        return Ok(result);
    }

    [HttpPut("branding")]
    public async Task<ActionResult<ApiResponse<VendorBrandingDto>>> UpdateBranding([FromBody] UpdateVendorBrandingDto dto)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<VendorBrandingDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));

        var result = await _authService.UpdateVendorBrandingAsync(VendorId, dto);
        if (result.Code == ResponseCodes.NOT_FOUND)
            return NotFound(result);
        if (result.Code == ResponseCodes.VALIDATION_ERROR)
            return BadRequest(result);
        return Ok(result);
    }

    [HttpGet("dashboard/stats")]
    public async Task<ActionResult<ApiResponse<VendorDashboardStatsDto>>> GetDashboardStats()
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<VendorDashboardStatsDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));

        var result = await _productService.GetDashboardStatsAsync(VendorId);
        return Ok(result);
    }

    [HttpGet("dashboard/orders")]
    public async Task<ActionResult<ApiResponse<List<OrderResponseDto>>>> GetDashboardOrders([FromQuery] DateTime? from, [FromQuery] DateTime? to)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<List<OrderResponseDto>>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _orderService.GetVendorOrdersAsync(VendorId, from, to);
        return Ok(result);
    }

    [HttpGet("dashboard/best-selling")]
    public async Task<ActionResult<ApiResponse<List<ProductResponseDto>>>> GetBestSelling([FromQuery] int limit = 10)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<List<ProductResponseDto>>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _productService.GetBestSellingAsync(VendorId, limit);
        return Ok(result);
    }

    [HttpGet("dashboard/analytics")]
    public async Task<ActionResult<ApiResponse<AnalyticsDto>>> GetAnalytics([FromQuery] int lastDays = 30)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<AnalyticsDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _orderService.GetVendorAnalyticsAsync(VendorId, lastDays);
        return Ok(result);
    }
}
