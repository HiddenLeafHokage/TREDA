using API.Attributes;
using API.Helpers;
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
    private readonly IFileStorageService _storage;
    private readonly ILogger<VendorController> _logger;

    public VendorController(
        IAuthService authService,
        IProductService productService,
        IOrderService orderService,
        IFileStorageService storage,
        ILogger<VendorController> logger)
    {
        _authService = authService;
        _productService = productService;
        _orderService = orderService;
        _storage = storage;
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

    /// <summary>
    /// Update the storefront appearance — shop logo and cover photo only. Send as multipart/form-data.
    /// Attach the image files directly as "logo" and/or "cover" (they are uploaded for you), or pass
    /// already-hosted URLs as the "businessLogoUrl" / "businessCoverPhotoUrl" form fields.
    /// The LOGO can be changed at most once every 6 months (early attempts are rejected and nothing
    /// changes). The COVER photo can be changed anytime.
    /// </summary>
    [HttpPut("store-appearance")]
    [Consumes("multipart/form-data")]
    public async Task<ActionResult<ApiResponse<VendorBrandingDto>>> UpdateStoreAppearance(
        [FromForm] UpdateVendorBrandingDto dto,
        IFormFile? logo,
        IFormFile? cover,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<VendorBrandingDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));

        var (logoError, logoStored) = await ImageUploadHelper.TryStoreAsync(logo, _storage, "logo", cancellationToken);
        if (logoError != null)
            return BadRequest(ApiResponse<VendorBrandingDto>.ErrorResult(logoError, ResponseCodes.VALIDATION_ERROR));
        if (logoStored != null)
            dto.BusinessLogoUrl = logoStored.Url;

        var (coverError, coverStored) = await ImageUploadHelper.TryStoreAsync(cover, _storage, "cover photo", cancellationToken);
        if (coverError != null)
        {
            await _storage.DeleteAsync(logoStored?.PublicId, cancellationToken); // don't orphan the logo
            return BadRequest(ApiResponse<VendorBrandingDto>.ErrorResult(coverError, ResponseCodes.VALIDATION_ERROR));
        }
        if (coverStored != null)
            dto.BusinessCoverPhotoUrl = coverStored.Url;

        var result = await _authService.UpdateVendorBrandingAsync(VendorId, dto);

        // If the save was rejected (e.g. the 6-month cooldown), delete anything we just uploaded.
        if (result.Code != ResponseCodes.SUCCESS)
        {
            await _storage.DeleteAsync(logoStored?.PublicId, cancellationToken);
            await _storage.DeleteAsync(coverStored?.PublicId, cancellationToken);
        }

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
