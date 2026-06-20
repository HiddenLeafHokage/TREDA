using API.Attributes;
using Application.Constants;
using Application.DTOs.Category;
using Application.DTOs.Common;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Persistence.Data;
using System.Security.Claims;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CategoriesController : ControllerBase
{
    private readonly TredaDbContext _context;

    public CategoriesController(TredaDbContext context)
    {
        _context = context;
    }

    /// <summary>List all product categories (Jiji-style). Use category Id when creating/updating a product. No auth required.</summary>
    [HttpGet]
    public async Task<ActionResult<ApiResponse<List<CategoryDto>>>> GetAll()
    {
        var list = await _context.ProductCategories
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
        return Ok(ApiResponse<List<CategoryDto>>.SuccessResult(list));
    }

    /// <summary>List only the product categories selected by the signed-in vendor.</summary>
    [HttpGet("my")]
    [SimpleAuthorize(AppConstants.Roles.Vendor, AppConstants.Roles.Admin)]
    public async Task<ActionResult<ApiResponse<List<CategoryDto>>>> GetMyCategories()
    {
        var vendorId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(vendorId))
            return Unauthorized(ApiResponse<List<CategoryDto>>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));

        var selectedCategoryIds = await _context.Users
            .Where(u => u.Id == vendorId)
            .Select(u => u.BusinessCategoryIds)
            .FirstOrDefaultAsync();

        var query = _context.ProductCategories.Where(c => c.IsActive);
        if (selectedCategoryIds is { Count: > 0 })
            query = query.Where(c => selectedCategoryIds.Contains(c.Id));

        var list = await query
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

        return Ok(ApiResponse<List<CategoryDto>>.SuccessResult(list));
    }
}
