using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Product;
using Application.DTOs.Vendor;
using Application.Helpers;
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
    private readonly IVendorTrafficService _traffic;

    public ProductService(TredaDbContext context, ILogger<ProductService> logger, IVendorTrafficService traffic)
    {
        _context = context;
        _logger = logger;
        _traffic = traffic;
    }

    public async Task<ApiResponse<ProductResponseDto>> CreateAsync(string vendorId, CreateProductDto dto)
    {
        var categoryId = NormalizeCategoryId(dto.CategoryId);
        var categoryError = await ValidateVendorCategoryAsync(vendorId, categoryId);
        if (categoryError != null)
            return ApiResponse<ProductResponseDto>.ErrorResult(categoryError, ResponseCodes.VALIDATION_ERROR);

        var imageValidationError = ValidateImageUrls(dto.ImageUrls);
        if (imageValidationError != null)
            return ApiResponse<ProductResponseDto>.ErrorResult(imageValidationError, ResponseCodes.VALIDATION_ERROR);

        try
        {
            var product = new Product
            {
                Id = Guid.NewGuid().ToString(),
                Name = dto.Name,
                Description = dto.Description ?? string.Empty,
                Price = dto.Price,
                CategoryId = categoryId,
                Condition = dto.Condition,
                ImageUrls = NormalizeImageUrls(dto.ImageUrls),
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

    public async Task<ApiResponse<PagedListDto<ProductResponseDto>>> GetVendorProductsAsync(string vendorId, string? search, string? categoryId, int page, int pageSize)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 200);

        var query = _context.Products
            .Include(p => p.Category)
            .Where(p => p.VendorId == vendorId);

        if (!string.IsNullOrWhiteSpace(categoryId))
            query = query.Where(p => p.CategoryId == categoryId);
        if (!string.IsNullOrWhiteSpace(search))
            query = query.Where(p => p.Name.Contains(search) || (p.Description != null && p.Description.Contains(search)));

        var total = await query.CountAsync();
        var list = await query
            .OrderByDescending(p => p.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        var pageDto = new PagedListDto<ProductResponseDto>
        {
            Items = list.Select(MapToDto).ToList(),
            Page = page,
            PageSize = pageSize,
            TotalCount = total,
            EmptyStateMessage = total == 0 ? AppConstants.EmptyStateMessages.ProductsNone : null
        };

        var msg = total == 0 ? AppConstants.EmptyStateMessages.ProductsNone : "Products loaded.";
        return ApiResponse<PagedListDto<ProductResponseDto>>.SuccessResult(pageDto, msg);
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
            var categoryId = NormalizeCategoryId(dto.CategoryId);
            var categoryError = await ValidateVendorCategoryAsync(vendorId, categoryId);
            if (categoryError != null)
                return ApiResponse<ProductResponseDto>.ErrorResult(categoryError, ResponseCodes.VALIDATION_ERROR);
            product.CategoryId = categoryId;
        }
        if (dto.Name != null) product.Name = dto.Name;
        if (dto.Description != null) product.Description = dto.Description;
        if (dto.Price.HasValue) product.Price = dto.Price.Value;
        if (dto.Condition.HasValue) product.Condition = dto.Condition.Value;
        if (dto.ImageUrls != null)
        {
            var imageValidationError = ValidateImageUrls(dto.ImageUrls);
            if (imageValidationError != null)
                return ApiResponse<ProductResponseDto>.ErrorResult(imageValidationError, ResponseCodes.VALIDATION_ERROR);

            product.ImageUrls = NormalizeImageUrls(dto.ImageUrls);
        }
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
            WalletBalance = walletBalance,
            SalesInsight = totalSales <= 0 ? AppConstants.EmptyStateMessages.DashboardNoRevenueYet : null
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
            return ApiResponse<List<ProductResponseDto>>.SuccessResult(new List<ProductResponseDto>(), AppConstants.EmptyStateMessages.BestSellingNone);

        var products = await _context.Products
            .Include(p => p.Category)
            .Where(p => productIds.Contains(p.Id))
            .ToListAsync();
        var ordered = productIds.Select(id => products.First(p => p.Id == id)).Select(MapToDto).ToList();
        return ApiResponse<List<ProductResponseDto>>.SuccessResult(ordered);
    }

    public async Task<ApiResponse<List<ProductResponseDto>>> ListPublicAsync(string? search, string? categoryId, int page = 1, int pageSize = 20)
    {
        var query = _context.Products
            .Include(p => p.Category)
            .Where(p => p.IsActive);

        if (!string.IsNullOrWhiteSpace(categoryId))
            query = query.Where(p => p.CategoryId == categoryId);
        if (!string.IsNullOrWhiteSpace(search))
            query = query.Where(p => p.Name.Contains(search) || (p.Description != null && p.Description.Contains(search)));

        var list = await query
            .OrderByDescending(p => p.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        if (!string.IsNullOrWhiteSpace(search))
            await _traffic.RecordSearchExposureAsync(list.Select(p => p.VendorId).Distinct().ToList(), search);

        var mapped = list.Select(MapToDto).ToList();
        var msg = mapped.Count == 0 ? AppConstants.EmptyStateMessages.PublicProductsNone : "Products loaded.";
        return ApiResponse<List<ProductResponseDto>>.SuccessResult(mapped, msg);
    }

    public async Task<ApiResponse<ProductWithVendorDto>> GetPublicByIdAsync(string productId)
    {
        var product = await _context.Products
            .Include(p => p.Category)
            .Include(p => p.Vendor)
            .FirstOrDefaultAsync(p => p.Id == productId && p.IsActive);
        if (product == null)
            return ApiResponse<ProductWithVendorDto>.ErrorResult("Product not found.", ResponseCodes.NOT_FOUND);

        var dto = new ProductWithVendorDto
        {
            Id = product.Id,
            Name = product.Name,
            Description = product.Description,
            Price = product.Price,
            CategoryId = product.CategoryId,
            CategoryName = product.Category?.Name ?? "",
            Condition = product.Condition.ToString(),
            Location = product.Location,
            ImageUrls = product.ImageUrls ?? new List<string>(),
            StockQuantity = product.StockQuantity,
            IsActive = product.IsActive,
            VendorId = product.VendorId,
            CreatedAt = product.CreatedAt,
            UpdatedAt = product.UpdatedAt,
            VendorName = product.Vendor?.FullName,
            VendorEmail = product.Vendor?.Email,
            VendorPhone = product.Vendor?.PhoneNumber,
            BusinessName = product.Vendor?.BusinessName,
            BusinessLocation = product.Vendor?.BusinessLocation,
            BusinessLogoUrl = product.Vendor?.BusinessLogoUrl,
            BusinessCoverPhotoUrl = product.Vendor?.BusinessCoverPhotoUrl,
            DisplayInitial = product.Vendor != null ? VendorBrandingHelper.GetDisplayInitial(product.Vendor) : "V"
        };
        await _traffic.RecordProductViewAsync(product.VendorId, product.Id);
        return ApiResponse<ProductWithVendorDto>.SuccessResult(dto);
    }

    public async Task<ApiResponse<VendorPublicProfileDto>> GetPublicVendorProfileAsync(string vendorId, string? categoryId, int page, int pageSize)
    {
        var vendor = await _context.Users.AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == vendorId && u.UserType == UserType.Vendor && u.IsActive);

        if (vendor == null)
            return ApiResponse<VendorPublicProfileDto>.ErrorResult("Vendor not found.", ResponseCodes.NOT_FOUND);

        return await BuildPublicVendorProfileAsync(vendor, categoryId, page, pageSize);
    }

    public async Task<ApiResponse<PagedListDto<VendorStoreListItemDto>>> ListPublicVendorsAsync(
        string? search, string? categoryId, string? location, int page, int pageSize)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 100);

        var normalizedCategoryId = string.IsNullOrWhiteSpace(categoryId) ? null : NormalizeCategoryId(categoryId);

        var query = _context.Users
            .AsNoTracking()
            .Where(u => u.UserType == UserType.Vendor && u.IsActive);

        if (!string.IsNullOrWhiteSpace(search))
        {
            var q = search.Trim();
            query = query.Where(u =>
                (u.BusinessName != null && u.BusinessName.Contains(q)) ||
                u.FullName.Contains(q) ||
                (u.BusinessCategory != null && u.BusinessCategory.Contains(q)));
        }

        if (!string.IsNullOrWhiteSpace(location))
        {
            var loc = location.Trim();
            query = query.Where(u => u.BusinessLocation != null && u.BusinessLocation.Contains(loc));
        }

        var filteredVendors = await query
            .OrderByDescending(u => u.CreatedAt)
            .ToListAsync();

        if (!string.IsNullOrWhiteSpace(normalizedCategoryId))
        {
            filteredVendors = filteredVendors
                .Where(u => u.BusinessCategoryIds.Contains(normalizedCategoryId, StringComparer.OrdinalIgnoreCase))
                .ToList();
        }

        var total = filteredVendors.Count;
        var vendors = filteredVendors
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();

        var vendorIds = vendors.Select(v => v.Id).ToList();
        var productCounts = await _context.Products
            .AsNoTracking()
            .Where(p => vendorIds.Contains(p.VendorId) && p.IsActive)
            .GroupBy(p => p.VendorId)
            .Select(g => new { VendorId = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.VendorId, x => x.Count);

        var items = vendors.Select(v => MapVendorStoreListItem(v, productCounts)).ToList();
        var pageDto = new PagedListDto<VendorStoreListItemDto>
        {
            Items = items,
            Page = page,
            PageSize = pageSize,
            TotalCount = total,
            EmptyStateMessage = total == 0 ? "No stores match your filters yet." : null
        };

        return ApiResponse<PagedListDto<VendorStoreListItemDto>>.SuccessResult(
            pageDto,
            total == 0 ? "No stores match your filters yet." : "Stores loaded.");
    }

    public async Task<ApiResponse<VendorPublicProfileDto>> GetPublicVendorProfileBySlugAsync(string slug, string? categoryId, int page, int pageSize)
    {
        var normalizedSlug = VendorSlugHelper.CreateSlug(slug);
        var vendor = await _context.Users.AsNoTracking()
            .FirstOrDefaultAsync(u => u.UserType == UserType.Vendor &&
                                      u.IsActive &&
                                      (u.BusinessSlug == normalizedSlug || u.BusinessSlug == slug));

        if (vendor == null)
        {
            var vendors = await _context.Users.AsNoTracking()
                .Where(u => u.UserType == UserType.Vendor && u.IsActive)
                .ToListAsync();
            vendor = vendors.FirstOrDefault(u => string.Equals(GetVendorSlug(u), normalizedSlug, StringComparison.OrdinalIgnoreCase));
        }

        if (vendor == null)
            return ApiResponse<VendorPublicProfileDto>.ErrorResult("Vendor not found.", ResponseCodes.NOT_FOUND);

        return await BuildPublicVendorProfileAsync(vendor, categoryId, page, pageSize);
    }

    public async Task<ApiResponse<bool>> RecordPublicProductEngagementAsync(string productId, VendorTrafficEventType eventType)
    {
        if (eventType is not (VendorTrafficEventType.ClickThrough or VendorTrafficEventType.Favourite))
            return ApiResponse<bool>.ErrorResult("Only ClickThrough or Favourite are allowed for this endpoint.", ResponseCodes.VALIDATION_ERROR);

        var product = await _context.Products.AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == productId && p.IsActive);
        if (product == null)
            return ApiResponse<bool>.ErrorResult("Product not found.", ResponseCodes.NOT_FOUND);

        await _traffic.RecordEngagementAsync(product.VendorId, product.Id, eventType);
        return ApiResponse<bool>.SuccessResult(true, "Engagement recorded.");
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

    private async Task<ApiResponse<VendorPublicProfileDto>> BuildPublicVendorProfileAsync(User vendor, string? categoryId, int page, int pageSize)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 100);

        var normalizedCategoryId = string.IsNullOrWhiteSpace(categoryId) ? null : NormalizeCategoryId(categoryId);

        var query = _context.Products
            .Include(p => p.Category)
            .Where(p => p.VendorId == vendor.Id && p.IsActive);

        if (!string.IsNullOrWhiteSpace(normalizedCategoryId))
            query = query.Where(p => p.CategoryId == normalizedCategoryId);

        var total = await query.CountAsync();
        var list = await query
            .OrderByDescending(p => p.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        var profile = MapVendorPublicProfile(vendor, list, page, pageSize, total);
        var msg = total == 0 ? AppConstants.EmptyStateMessages.PublicProductsNone : "Vendor storefront loaded.";
        return ApiResponse<VendorPublicProfileDto>.SuccessResult(profile, msg);
    }

    private static VendorStoreListItemDto MapVendorStoreListItem(User vendor, IReadOnlyDictionary<string, int> productCounts)
    {
        return new VendorStoreListItemDto
        {
            Id = vendor.Id,
            Slug = GetVendorSlug(vendor),
            BusinessName = vendor.BusinessName ?? vendor.FullName,
            BusinessCategory = vendor.BusinessCategory,
            BusinessCategoryIds = vendor.BusinessCategoryIds,
            BusinessLocation = vendor.BusinessLocation,
            BusinessLogoUrl = vendor.BusinessLogoUrl,
            BusinessCoverPhotoUrl = vendor.BusinessCoverPhotoUrl,
            DisplayInitial = VendorBrandingHelper.GetDisplayInitial(vendor),
            ProductCount = productCounts.TryGetValue(vendor.Id, out var count) ? count : 0,
            Rating = 0,
            ReviewCount = 0
        };
    }

    private static VendorPublicProfileDto MapVendorPublicProfile(
        User vendor,
        IReadOnlyList<Product> products,
        int page,
        int pageSize,
        int total)
    {
        return new VendorPublicProfileDto
        {
            Id = vendor.Id,
            Slug = GetVendorSlug(vendor),
            BusinessName = vendor.BusinessName ?? vendor.FullName,
            BusinessCategory = vendor.BusinessCategory,
            BusinessCategoryIds = vendor.BusinessCategoryIds,
            BusinessLocation = vendor.BusinessLocation,
            ShopDescription = vendor.ShopDescription,
            PhoneNumber = vendor.PhoneNumber,
            BusinessLogoUrl = vendor.BusinessLogoUrl,
            BusinessCoverPhotoUrl = vendor.BusinessCoverPhotoUrl,
            DisplayInitial = VendorBrandingHelper.GetDisplayInitial(vendor),
            CreatedAt = vendor.CreatedAt,
            YearsOnTreda = Math.Max(0, (int)((DateTime.UtcNow.Date - vendor.CreatedAt.Date).TotalDays / 365.25)),
            IsVerified = !string.IsNullOrWhiteSpace(vendor.CAC_RC_Number),
            Rating = 0,
            ReviewCount = 0,
            Products = new PagedListDto<ProductResponseDto>
            {
                Items = products.Select(MapToDto).ToList(),
                Page = page,
                PageSize = pageSize,
                TotalCount = total,
                EmptyStateMessage = total == 0 ? AppConstants.EmptyStateMessages.PublicProductsNone : null
            }
        };
    }

    private static string GetVendorSlug(User vendor)
        => string.IsNullOrWhiteSpace(vendor.BusinessSlug)
            ? VendorSlugHelper.CreateSlug(vendor.BusinessName ?? vendor.FullName)
            : vendor.BusinessSlug;

    private async Task<string?> ValidateVendorCategoryAsync(string vendorId, string categoryId)
    {
        var categoryExists = await _context.ProductCategories
            .AnyAsync(c => c.Id == categoryId && c.IsActive);
        if (!categoryExists)
            return "Invalid or inactive category. Use GET /api/categories for valid category IDs.";

        var selectedCategoryIds = await _context.Users
            .Where(u => u.Id == vendorId)
            .Select(u => u.BusinessCategoryIds)
            .FirstOrDefaultAsync();

        if (selectedCategoryIds == null || selectedCategoryIds.Count == 0)
            return null;

        if (!selectedCategoryIds.Contains(categoryId, StringComparer.OrdinalIgnoreCase))
            return "You can only add products under the categories selected in your vendor profile.";

        return null;
    }

    private static string NormalizeCategoryId(string categoryId)
    {
        var trimmed = categoryId.Trim();
        return ProductCategorySeed.LegacyIdMap.TryGetValue(trimmed, out var mapped) ? mapped : trimmed;
    }

    private static List<string> NormalizeImageUrls(List<string>? imageUrls)
    {
        return imageUrls?
            .Select(u => u?.Trim())
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .Select(u => u!.StartsWith("uploads/", StringComparison.OrdinalIgnoreCase) ? $"/{u}" : u)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList() ?? new List<string>();
    }

    private static string? ValidateImageUrls(List<string>? imageUrls)
    {
        if (imageUrls == null || imageUrls.Count == 0)
            return null;

        var normalized = NormalizeImageUrls(imageUrls);
        if (normalized.Count > AppConstants.MaxProductImagesPerProduct)
        {
            return $"A product can have at most {AppConstants.MaxProductImagesPerProduct} images. Upload with POST /api/upload or POST /api/upload/batch, then send all URLs in imageUrls.";
        }

        foreach (var url in normalized)
        {
            if (url.StartsWith("blob:", StringComparison.OrdinalIgnoreCase))
                return "Product image URLs cannot be browser blob URLs. Upload the image with POST /api/upload first, then save the returned data.url in imageUrls.";

            if (url.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
                return "Product image URLs cannot be local file URLs. Upload the image with POST /api/upload first, then save the returned data.url in imageUrls.";

            if (url.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                return "Product image URLs cannot be data URLs. Upload the image with POST /api/upload first, then save the returned data.url in imageUrls.";

            if (url.StartsWith("/uploads/", StringComparison.OrdinalIgnoreCase) ||
                url.StartsWith("uploads/", StringComparison.OrdinalIgnoreCase))
                continue;

            if (Uri.TryCreate(url, UriKind.Absolute, out var parsed) &&
                (parsed.Scheme == Uri.UriSchemeHttp || parsed.Scheme == Uri.UriSchemeHttps))
                continue;

            return $"Invalid product image URL '{url}'. Use an http/https URL or upload the image with POST /api/upload and save the returned data.url.";
        }

        return null;
    }
}
