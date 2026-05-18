using API.Attributes;
using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Product;
using Application.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
[SimpleAuthorize(AppConstants.Roles.Vendor, AppConstants.Roles.Admin)]
public class ProductsController : ControllerBase
{
    private readonly IProductService _productService;
    private readonly ILogger<ProductsController> _logger;

    public ProductsController(IProductService productService, ILogger<ProductsController> logger)
    {
        _productService = productService;
        _logger = logger;
    }

    private string? SellerId => User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    [HttpGet]
    public async Task<ActionResult<ApiResponse<PagedListDto<ProductResponseDto>>>> GetMyProducts(
        [FromQuery] string? search,
        [FromQuery] string? categoryId,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20)
    {
        if (string.IsNullOrEmpty(SellerId))
            return Unauthorized(ApiResponse<PagedListDto<ProductResponseDto>>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));

        var result = await _productService.GetVendorProductsAsync(SellerId, search, categoryId, page, pageSize);
        return Ok(result);
    }

    /// <summary>All products for this vendor (no pagination). Prefer GET with page/pageSize for large catalogs.</summary>
    [HttpGet("all")]
    public async Task<ActionResult<ApiResponse<List<ProductResponseDto>>>> GetAllMyProducts()
    {
        if (string.IsNullOrEmpty(SellerId))
            return Unauthorized(ApiResponse<List<ProductResponseDto>>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _productService.GetBySellerIdAsync(SellerId);
        return Ok(result);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<ApiResponse<ProductResponseDto>>> GetById(string id)
    {
        if (string.IsNullOrEmpty(SellerId))
            return Unauthorized(ApiResponse<ProductResponseDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));

        var result = await _productService.GetByIdAsync(id, SellerId);
        if (result.Code == ResponseCodes.NOT_FOUND)
            return NotFound(result);
        return Ok(result);
    }

    [HttpPost]
    public async Task<ActionResult<ApiResponse<ProductResponseDto>>> Create([FromBody] CreateProductDto dto)
    {
        if (string.IsNullOrEmpty(SellerId))
            return Unauthorized(ApiResponse<ProductResponseDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));

        var result = await _productService.CreateAsync(SellerId, dto);
        if (result.Code == ResponseCodes.VALIDATION_ERROR)
            return BadRequest(result);
        if (!result.Success)
            return StatusCode(500, result);
        return CreatedAtAction(nameof(GetById), new { id = result.Data!.Id }, result);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<ApiResponse<ProductResponseDto>>> Update(string id, [FromBody] UpdateProductDto dto)
    {
        if (string.IsNullOrEmpty(SellerId))
            return Unauthorized(ApiResponse<ProductResponseDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));

        var result = await _productService.UpdateAsync(id, SellerId, dto);
        if (result.Code == ResponseCodes.NOT_FOUND)
            return NotFound(result);
        return Ok(result);
    }

    [HttpDelete("{id}")]
    public async Task<ActionResult<ApiResponse<bool>>> Delete(string id)
    {
        if (string.IsNullOrEmpty(SellerId))
            return Unauthorized(ApiResponse<bool>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));

        var result = await _productService.DeleteAsync(id, SellerId);
        if (result.Code == ResponseCodes.NOT_FOUND)
            return NotFound(result);
        return Ok(result);
    }
}
