using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Product;
using Application.DTOs.Vendor;
using Domain.Enums;

namespace Application.Interfaces;

public interface IProductService
{
    Task<ApiResponse<ProductResponseDto>> CreateAsync(string sellerId, CreateProductDto dto);
    Task<ApiResponse<ProductResponseDto>> GetByIdAsync(string productId, string sellerId);
    Task<ApiResponse<List<ProductResponseDto>>> GetBySellerIdAsync(string sellerId);
    Task<ApiResponse<PagedListDto<ProductResponseDto>>> GetVendorProductsAsync(string vendorId, string? search, string? categoryId, int page, int pageSize);
    Task<ApiResponse<ProductResponseDto>> UpdateAsync(string productId, string sellerId, UpdateProductDto dto);
    Task<ApiResponse<bool>> DeleteAsync(string productId, string sellerId);
    Task<ApiResponse<ProductResponseDto>> PublishAsync(string productId, string sellerId);
    Task<ApiResponse<VendorDashboardStatsDto>> GetDashboardStatsAsync(string sellerId);
    Task<ApiResponse<List<ProductResponseDto>>> GetBestSellingAsync(string sellerId, int limit = AppConstants.DefaultBestSellingLimit);
    Task<ApiResponse<List<ProductResponseDto>>> ListPublicAsync(string? search, string? categoryId, int page = 1, int pageSize = 20);
    Task<ApiResponse<ProductWithVendorDto>> GetPublicByIdAsync(string productId);
    Task<ApiResponse<bool>> RecordPublicProductEngagementAsync(string productId, VendorTrafficEventType eventType);
    Task<ApiResponse<VendorPublicProfileDto>> GetPublicVendorProfileAsync(string vendorId, string? categoryId, int page, int pageSize);
    Task<ApiResponse<PagedListDto<VendorStoreListItemDto>>> ListPublicVendorsAsync(
        string? search, string? categoryId, string? location, int page, int pageSize);
    Task<ApiResponse<VendorPublicProfileDto>> GetPublicVendorProfileBySlugAsync(string slug, string? categoryId, int page, int pageSize);

    Task<ApiResponse<bool>> SetPromotedAsync(string productId, string vendorId, bool promoted);
    Task<ApiResponse<List<VendorStoreListItemDto>>> ListTopStoresAsync(int limit);
    Task<ApiResponse<List<ProductResponseDto>>> ListFeaturedProductsAsync(int limit);
}
