using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Product;
using Application.DTOs.Vendor;
using Application.Interfaces;
using Domain.Entities;
using Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Persistence.Data;

namespace Application.Services;

public class ProductService : IProductService
{
    private readonly TredaDbContext _context;
    private readonly ILogger<ProductService> _logger;

    public ProductService(TredaDbContext context, ILogger<ProductService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<ApiResponse<ProductResponseDto>> CreateAsync(string vendorId, CreateProductDto dto)
    {
        var categoryExists = await _context.ProductCategories.AnyAsync(c => c.Id == dto.CategoryId && c.IsActive);
        if (!categoryExists)
            return ApiResponse<ProductResponseDto>.ErrorResult("Invalid or inactive category. Use GET /api/categories for valid category IDs.", ResponseCodes.VALIDATION_ERROR);

        try
        {
            var product = new Product
            {
                Id = Guid.NewGuid().ToString(),
                Name = dto.Name,
                Description = dto.Description ?? string.Empty,
                Price = dto.Price,
                CategoryId = dto.CategoryId,
                Condition = dto.Condition,
                Location = dto.Location,
                ImageUrls = dto.ImageUrls ?? new List<string>(),
                StockQuantity = dto.StockQuantity,
                IsActive = dto.IsActive,
                VendorId = vendorId,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _context.Products.Add(product);
            await _context.SaveChangesAsync();
            await _context.Entry(product).Reference(p => p.Category).LoadAsync();

            return ApiResponse<ProductResponseDto>.SuccessResult(
                MapToDto(product),
                "Product created successfully.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating product for vendor {VendorId}", vendorId);
            return ApiResponse<ProductResponseDto>.ErrorResult(
                "An error occurred while creating the product.",
                ResponseCodes.SERVER_ERROR);
        }
    }

    public async Task<ApiResponse<ProductResponseDto>> GetByIdAsync(string productId, string vendorId)
    {
        var product = await _context.Products
            .Include(p => p.Category)
            .FirstOrDefaultAsync(p => p.Id == productId && p.VendorId == vendorId);

        if (product == null)
            return ApiResponse<ProductResponseDto>.ErrorResult("Product not found.", ResponseCodes.NOT_FOUND);

        return ApiResponse<ProductResponseDto>.SuccessResult(MapToDto(product));
    }

    public async Task<ApiResponse<List<ProductResponseDto>>> GetBySellerIdAsync(string vendorId)
    {
        var products = await _context.Products
            .Include(p => p.Category)
            .Where(p => p.VendorId == vendorId)
            .OrderByDescending(p => p.CreatedAt)
            .ToListAsync();

        var dtos = products.Select(MapToDto).ToList();
        return ApiResponse<List<ProductResponseDto>>.SuccessResult(dtos);
    }

    public async Task<ApiResponse<ProductResponseDto>> UpdateAsync(string productId, string vendorId, UpdateProductDto dto)
    {
        var product = await _context.Products
            .Include(p => p.Category)
            .FirstOrDefaultAsync(p => p.Id == productId && p.VendorId == vendorId);

        if (product == null)
            return ApiResponse<ProductResponseDto>.ErrorResult("Product not found.", ResponseCodes.NOT_FOUND);

        if (dto.CategoryId != null)
        {
            var categoryExists = await _context.ProductCategories.AnyAsync(c => c.Id == dto.CategoryId && c.IsActive);
            if (!categoryExists)
                return ApiResponse<ProductResponseDto>.ErrorResult("Invalid or inactive category.", ResponseCodes.VALIDATION_ERROR);
            product.CategoryId = dto.CategoryId;
        }
        if (dto.Name != null) product.Name = dto.Name;
        if (dto.Description != null) product.Description = dto.Description;
        if (dto.Price.HasValue) product.Price = dto.Price.Value;
        if (dto.Condition.HasValue) product.Condition = dto.Condition.Value;
        if (dto.Location != null) product.Location = dto.Location;
        if (dto.ImageUrls != null) product.ImageUrls = dto.ImageUrls;
        if (dto.StockQuantity.HasValue) product.StockQuantity = dto.StockQuantity.Value;
        if (dto.IsActive.HasValue) product.IsActive = dto.IsActive.Value;

        product.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        return ApiResponse<ProductResponseDto>.SuccessResult(MapToDto(product), "Product updated successfully.");
    }

    public async Task<ApiResponse<bool>> DeleteAsync(string productId, string vendorId)
    {
        var product = await _context.Products
            .FirstOrDefaultAsync(p => p.Id == productId && p.VendorId == vendorId);

        if (product == null)
            return ApiResponse<bool>.ErrorResult("Product not found.", ResponseCodes.NOT_FOUND);

        _context.Products.Remove(product);
        await _context.SaveChangesAsync();
        return ApiResponse<bool>.SuccessResult(true, "Product deleted successfully.");
    }

    public async Task<ApiResponse<VendorDashboardStatsDto>> GetDashboardStatsAsync(string vendorId)
    {
        var total = await _context.Products.CountAsync(p => p.VendorId == vendorId);
        var active = await _context.Products.CountAsync(p => p.VendorId == vendorId && p.IsActive);

        var todayStart = DateTime.UtcNow.Date;
        var ordersToday = await _context.Orders.CountAsync(o => o.VendorId == vendorId && o.CreatedAt >= todayStart);
        var pendingOrders = await _context.Orders.CountAsync(o => o.VendorId == vendorId && o.Status == OrderStatus.Pending);
        var totalSales = await _context.Orders
            .Where(o => o.VendorId == vendorId && (o.Status == OrderStatus.Shipped || o.Status == OrderStatus.Completed))
            .SumAsync(o => o.Amount);

        var wallet = await _context.VendorWallets.FirstOrDefaultAsync(w => w.VendorId == vendorId);
        var walletBalance = wallet?.Balance ?? 0;

        var stats = new VendorDashboardStatsDto
        {
            TotalProducts = total,
            ActiveProducts = active,
            TotalSales = totalSales,
            OrdersToday = ordersToday,
            PendingOrders = pendingOrders,
            WalletBalance = walletBalance
        };
        return ApiResponse<VendorDashboardStatsDto>.SuccessResult(stats);
    }

    public async Task<ApiResponse<List<ProductResponseDto>>> GetBestSellingAsync(string vendorId, int limit = AppConstants.DefaultBestSellingLimit)
    {
        var productIds = await _context.Orders
            .Where(o => o.VendorId == vendorId && o.ProductId != null && (o.Status == OrderStatus.Shipped || o.Status == OrderStatus.Completed))
            .GroupBy(o => o.ProductId!)
            .OrderByDescending(g => g.Count())
            .Take(limit)
            .Select(g => g.Key)
            .ToListAsync();

        if (productIds.Count == 0)
            return ApiResponse<List<ProductResponseDto>>.SuccessResult(new List<ProductResponseDto>());

        var products = await _context.Products
            .Include(p => p.Category)
            .Where(p => productIds.Contains(p.Id))
            .ToListAsync();
        var ordered = productIds.Select(id => products.First(p => p.Id == id)).Select(MapToDto).ToList();
        return ApiResponse<List<ProductResponseDto>>.SuccessResult(ordered);
    }

    private static ProductResponseDto MapToDto(Product p)
    {
        return new ProductResponseDto
        {
            Id = p.Id,
            Name = p.Name,
            Description = p.Description,
            Price = p.Price,
            CategoryId = p.CategoryId,
            CategoryName = p.Category?.Name ?? "",
            Condition = p.Condition.ToString(),
            Location = p.Location,
            ImageUrls = p.ImageUrls ?? new List<string>(),
            StockQuantity = p.StockQuantity,
            IsActive = p.IsActive,
            VendorId = p.VendorId,
            CreatedAt = p.CreatedAt,
            UpdatedAt = p.UpdatedAt
        };
    }
}
