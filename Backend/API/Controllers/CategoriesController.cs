using Application.DTOs.Category;
using Application.DTOs.Common;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Persistence.Data;

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
}
