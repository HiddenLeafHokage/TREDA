using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Product;
using Application.DTOs.Vendor;

namespace Application.Interfaces;

public interface IProductService
{
    Task<ApiResponse<ProductResponseDto>> CreateAsync(string sellerId, CreateProductDto dto);
    Task<ApiResponse<ProductResponseDto>> GetByIdAsync(string productId, string sellerId);
    Task<ApiResponse<List<ProductResponseDto>>> GetBySellerIdAsync(string sellerId);
    Task<ApiResponse<ProductResponseDto>> UpdateAsync(string productId, string sellerId, UpdateProductDto dto);
    Task<ApiResponse<bool>> DeleteAsync(string productId, string sellerId);
    Task<ApiResponse<VendorDashboardStatsDto>> GetDashboardStatsAsync(string sellerId);
    Task<ApiResponse<List<ProductResponseDto>>> GetBestSellingAsync(string sellerId, int limit = AppConstants.DefaultBestSellingLimit);
}
