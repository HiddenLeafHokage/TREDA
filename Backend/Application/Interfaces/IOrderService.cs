using Application.DTOs.Common;
using Application.DTOs.Order;

namespace Application.Interfaces;

public interface IOrderService
{
    Task<ApiResponse<OrderResponseDto>> CreateGuestOrderAsync(CreateGuestOrderDto dto);
    Task<ApiResponse<OrderResponseDto>> GetByIdAsync(string orderId, string vendorId);
    Task<ApiResponse<List<OrderResponseDto>>> GetVendorOrdersAsync(string vendorId, DateTime? from, DateTime? to);
    Task<ApiResponse<PagedListDto<OrderResponseDto>>> GetVendorOrdersPagedAsync(
        string vendorId, string? search, string? status, DateTime? from, DateTime? to, int page, int pageSize);
    Task<ApiResponse<OrderResponseDto>> UpdateStatusAsync(string orderId, string vendorId, UpdateOrderStatusDto dto);
    Task<ApiResponse<OrderResponseDto>> UpdateOrderAsync(string orderId, string vendorId, UpdateOrderDto dto);
    Task<ApiResponse<OrderResponseDto>> UpdatePaymentStatusAsync(string orderId, string vendorId, UpdatePaymentStatusDto dto);
    Task<ApiResponse<InvoiceDto>> GetInvoiceAsync(string orderId, string vendorId);
    Task<ApiResponse<Application.DTOs.Vendor.AnalyticsDto>> GetVendorAnalyticsAsync(string vendorId, int lastDays = 30);
}
