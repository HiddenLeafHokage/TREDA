using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Order;
using Application.Interfaces;
using Domain.Entities;
using Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Persistence.Data;

namespace Application.Services;

public class OrderService : IOrderService
{
    private readonly TredaDbContext _context;
    private readonly ILogger<OrderService> _logger;

    public OrderService(TredaDbContext context, ILogger<OrderService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<ApiResponse<OrderResponseDto>> CreateAsync(string vendorId, CreateOrderDto dto)
    {
        var order = new Order
        {
            Id = Guid.NewGuid().ToString(),
            VendorId = vendorId,
            BuyerId = dto.BuyerId,
            ProductId = dto.ProductId,
            Amount = dto.Amount,
            CustomerName = dto.CustomerName,
            Status = OrderStatus.Pending,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        _context.Orders.Add(order);
        await _context.SaveChangesAsync();

        var withProduct = await _context.Orders
            .Include(o => o.Product)
            .FirstAsync(o => o.Id == order.Id);
        return ApiResponse<OrderResponseDto>.SuccessResult(MapToDto(withProduct), "Order created.");
    }

    public async Task<ApiResponse<OrderResponseDto>> GetByIdAsync(string orderId, string vendorId)
    {
        var order = await _context.Orders
            .Include(o => o.Product)
            .FirstOrDefaultAsync(o => o.Id == orderId && o.VendorId == vendorId);
        if (order == null)
            return ApiResponse<OrderResponseDto>.ErrorResult("Order not found.", ResponseCodes.NOT_FOUND);
        return ApiResponse<OrderResponseDto>.SuccessResult(MapToDto(order));
    }

    public async Task<ApiResponse<List<OrderResponseDto>>> GetVendorOrdersAsync(string vendorId, DateTime? from, DateTime? to)
    {
        var query = _context.Orders
            .Include(o => o.Product)
            .Where(o => o.VendorId == vendorId);

        if (from.HasValue) query = query.Where(o => o.CreatedAt >= from.Value);
        if (to.HasValue) query = query.Where(o => o.CreatedAt <= to.Value);

        var list = await query.OrderByDescending(o => o.CreatedAt).ToListAsync();
        var dtos = list.Select(MapToDto).ToList();
        return ApiResponse<List<OrderResponseDto>>.SuccessResult(dtos);
    }

    public async Task<ApiResponse<OrderResponseDto>> UpdateStatusAsync(string orderId, string vendorId, UpdateOrderStatusDto dto)
    {
        var order = await _context.Orders
            .Include(o => o.Product)
            .FirstOrDefaultAsync(o => o.Id == orderId && o.VendorId == vendorId);
        if (order == null)
            return ApiResponse<OrderResponseDto>.ErrorResult("Order not found.", ResponseCodes.NOT_FOUND);
        order.Status = dto.Status;
        order.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
        return ApiResponse<OrderResponseDto>.SuccessResult(MapToDto(order), "Order updated.");
    }

    private static OrderResponseDto MapToDto(Order o)
    {
        var take = Math.Min(AppConstants.OrderIdDisplayLength, o.Id.Length);
        var orderIdDisplay = AppConstants.OrderIdDisplayPrefix + o.Id[..take].ToUpperInvariant();
        return new OrderResponseDto
        {
            Id = o.Id,
            OrderIdDisplay = orderIdDisplay,
            CustomerName = o.CustomerName,
            Amount = o.Amount,
            Status = o.Status.ToString(),
            ProductId = o.ProductId,
            ProductName = o.Product?.Name,
            CreatedAt = o.CreatedAt
        };
    }
}
