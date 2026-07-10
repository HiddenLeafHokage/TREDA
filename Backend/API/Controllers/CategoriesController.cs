using API.Attributes;
using Application.Constants;
using Application.DTOs.Category;
using Application.DTOs.Common;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Persistence.Data;
using System.Security.Claims;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CategoriesController : ControllerBase
{
    private const string ActiveCategoriesCacheKey = "categories:active";
    private static readonly TimeSpan CacheDuration = TimeSpan.FromHours(1);

    private readonly TredaDbContext _context;
    private readonly IMemoryCache _cache;

    public CategoriesController(TredaDbContext context, IMemoryCache cache)
    {
        _context = context;
        _cache = cache;
    }

    /// <summary>List all product categories (Jiji-style). Use category Id when creating/updating a product. No auth required.</summary>
    [HttpGet]
    public async Task<ActionResult<ApiResponse<List<CategoryDto>>>> GetAll()
        => Ok(ApiResponse<List<CategoryDto>>.SuccessResult(await GetActiveCategoriesAsync()));

    /// <summary>List only the product categories selected by the signed-in vendor.</summary>
    [HttpGet("my")]
    [SimpleAuthorize(AppConstants.Roles.Vendor, AppConstants.Roles.Admin)]
    public async Task<ActionResult<ApiResponse<List<CategoryDto>>>> GetMyCategories()
    {
        var vendorId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(vendorId))
            return Unauthorized(ApiResponse<List<CategoryDto>>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));

        var selectedCategoryIds = await _context.Users
            .AsNoTracking()
            .Where(u => u.Id == vendorId)
            .Select(u => u.BusinessCategoryIds)
            .FirstOrDefaultAsync();

        var all = await GetActiveCategoriesAsync();
        var list = selectedCategoryIds is { Count: > 0 }
            ? all.Where(c => selectedCategoryIds.Contains(c.Id)).ToList()
            : all;

        return Ok(ApiResponse<List<CategoryDto>>.SuccessResult(list));
    }

    /// <summary>
    /// Active categories, cached in memory. They only change via a migration/seed, so a DB hit on
    /// every request is pure waste. Cache is per-instance — swap for Redis if you scale out.
    /// </summary>
    private async Task<List<CategoryDto>> GetActiveCategoriesAsync()
    {
        if (_cache.TryGetValue(ActiveCategoriesCacheKey, out List<CategoryDto>? cached) && cached is not null)
            return cached;

        var list = await _context.ProductCategories
            .AsNoTracking()
            .Where(c => c.IsActive)
            .OrderBy(c => c.DisplayOrder)
            .Select(c => new CategoryDto
            {
                Id = c.Id,
                Name = c.Name,
                Slug = c.Slug,
                Description = c.Description,
                DisplayOrder = c.DisplayOrder
            })
            .ToListAsync();

        _cache.Set(ActiveCategoriesCacheKey, list, CacheDuration);
        return list;
    }
}
