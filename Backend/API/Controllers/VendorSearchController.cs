using API.Attributes;
using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Vendor;
using Application.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace API.Controllers;

/// <summary>Global search across the signed-in vendor's products, orders, and conversations.</summary>
[ApiController]
[Route("api/vendor/search")]
[SimpleAuthorize(AppConstants.Roles.Vendor, AppConstants.Roles.Admin)]
public class VendorSearchController : ControllerBase
{
    private readonly IVendorSearchService _search;

    public VendorSearchController(IVendorSearchService search)
    {
        _search = search;
    }

    private string? VendorId => User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    [HttpGet]
    public async Task<ActionResult<ApiResponse<VendorSearchResultDto>>> Search(
        [FromQuery] string q,
        [FromQuery] int perSectionLimit = 5)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<VendorSearchResultDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _search.SearchAsync(VendorId, q, perSectionLimit);
        if (result.Code == ResponseCodes.VALIDATION_ERROR) return BadRequest(result);
        return Ok(result);
    }
}
