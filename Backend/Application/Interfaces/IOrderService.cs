using Application.DTOs.Common;
using Application.DTOs.Order;

namespace Application.Interfaces;

public interface IOrderService
{
    Task<ApiResponse<OrderResponseDto>> CreateAsync(string vendorId, CreateOrderDto dto);
    Task<ApiResponse<OrderResponseDto>> GetByIdAsync(string orderId, string vendorId);
    Task<ApiResponse<List<OrderResponseDto>>> GetVendorOrdersAsync(string vendorId, DateTime? from, DateTime? to);
    Task<ApiResponse<OrderResponseDto>> UpdateStatusAsync(string orderId, string vendorId, UpdateOrderStatusDto dto);
}
