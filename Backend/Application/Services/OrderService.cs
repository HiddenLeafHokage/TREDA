using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Order;
using Application.DTOs.Vendor;
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
    private readonly IVendorNotificationService _notifications;

    public OrderService(TredaDbContext context, ILogger<OrderService> logger, IVendorNotificationService notifications)
    {
        _context = context;
        _logger = logger;
        _notifications = notifications;
    }

    public async Task<ApiResponse<OrderResponseDto>> CreateAsync(string vendorId, CreateOrderDto dto)
    {
        var isGuest = !string.IsNullOrWhiteSpace(dto.GuestEmail);
        if (isGuest && string.IsNullOrWhiteSpace(dto.GuestName))
            return ApiResponse<OrderResponseDto>.ErrorResult("GuestName is required when using GuestEmail.", ResponseCodes.VALIDATION_ERROR);
        if (!isGuest && string.IsNullOrWhiteSpace(dto.BuyerId))
            return ApiResponse<OrderResponseDto>.ErrorResult("Either BuyerId or GuestEmail+GuestName is required.", ResponseCodes.VALIDATION_ERROR);

        var order = new Order
        {
            Id = Guid.NewGuid().ToString(),
            VendorId = vendorId,
            BuyerId = isGuest ? null : dto.BuyerId,
            GuestEmail = dto.GuestEmail,
            GuestName = dto.GuestName,
            ProductId = dto.ProductId,
            Amount = dto.Amount,
            CustomerName = !string.IsNullOrWhiteSpace(dto.CustomerName) ? dto.CustomerName : (dto.GuestName ?? dto.CustomerName),
            Status = OrderStatus.Pending,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        _context.Orders.Add(order);
        await _context.SaveChangesAsync();

        var withProduct = await _context.Orders
            .Include(o => o.Product)
            .FirstAsync(o => o.Id == order.Id);
        await _notifications.NotifyNewOrderAsync(withProduct, withProduct.Product?.Name);
        return ApiResponse<OrderResponseDto>.SuccessResult(MapToDto(withProduct), "Order created.");
    }

    public async Task<ApiResponse<OrderResponseDto>> CreateGuestOrderAsync(CreateGuestOrderDto dto)
    {
        var vendorExists = await _context.Users.AnyAsync(u => u.Id == dto.VendorId && u.UserType == Domain.Enums.UserType.Vendor);
        if (!vendorExists)
            return ApiResponse<OrderResponseDto>.ErrorResult("Vendor not found.", ResponseCodes.NOT_FOUND);
        if (!string.IsNullOrEmpty(dto.ProductId))
        {
            var productExists = await _context.Products.AnyAsync(p => p.Id == dto.ProductId && p.VendorId == dto.VendorId);
            if (!productExists)
                return ApiResponse<OrderResponseDto>.ErrorResult("Product not found.", ResponseCodes.NOT_FOUND);
        }

        var order = new Order
        {
            Id = Guid.NewGuid().ToString(),
            VendorId = dto.VendorId,
            BuyerId = null,
            GuestEmail = dto.GuestEmail,
            GuestName = dto.GuestName,
            ProductId = dto.ProductId,
            Amount = dto.Amount,
            CustomerName = dto.GuestName,
            Status = OrderStatus.Pending,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        _context.Orders.Add(order);
        await _context.SaveChangesAsync();

        var withProduct = await _context.Orders.Include(o => o.Product).FirstAsync(o => o.Id == order.Id);
        await _notifications.NotifyNewOrderAsync(withProduct, withProduct.Product?.Name);
        return ApiResponse<OrderResponseDto>.SuccessResult(MapToDto(withProduct), "Order/inquiry created. Seller can contact you to negotiate.");
    }

    public async Task<ApiResponse<OrderResponseDto>> UpdateOrderAsync(string orderId, string vendorId, UpdateOrderDto dto)
    {
        var order = await _context.Orders
            .Include(o => o.Product)
            .FirstOrDefaultAsync(o => o.Id == orderId && o.VendorId == vendorId);
        if (order == null)
            return ApiResponse<OrderResponseDto>.ErrorResult("Order not found.", ResponseCodes.NOT_FOUND);
        var prevStatus = order.Status;
        if (dto.Status.HasValue) order.Status = dto.Status.Value;
        if (dto.Amount.HasValue) order.Amount = dto.Amount.Value;
        order.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
        if (order.Status == OrderStatus.Completed && prevStatus != OrderStatus.Completed)
            await _notifications.NotifyOrderPaymentConfirmedAsync(order, order.Product?.Name);
        return ApiResponse<OrderResponseDto>.SuccessResult(MapToDto(order), "Order updated.");
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
        var msg = dtos.Count == 0 ? AppConstants.EmptyStateMessages.OrdersNone : "Orders loaded.";
        return ApiResponse<List<OrderResponseDto>>.SuccessResult(dtos, msg);
    }

    public async Task<ApiResponse<PagedListDto<OrderResponseDto>>> GetVendorOrdersPagedAsync(
        string vendorId, string? search, string? status, DateTime? from, DateTime? to, int page, int pageSize)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 200);

        var query = _context.Orders
            .Include(o => o.Product)
            .Where(o => o.VendorId == vendorId);

        if (from.HasValue) query = query.Where(o => o.CreatedAt >= from.Value);
        if (to.HasValue) query = query.Where(o => o.CreatedAt <= to.Value);
        if (!string.IsNullOrWhiteSpace(search))
            query = query.Where(o => o.CustomerName.Contains(search) || o.Id.Contains(search) || (o.GuestEmail != null && o.GuestEmail.Contains(search)));
        if (!string.IsNullOrWhiteSpace(status) && !string.Equals(status, "all", StringComparison.OrdinalIgnoreCase))
        {
            if (Enum.TryParse<OrderStatus>(status, true, out var st))
                query = query.Where(o => o.Status == st);
        }

        var total = await query.CountAsync();
        var list = await query
            .OrderByDescending(o => o.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        var pageDto = new PagedListDto<OrderResponseDto>
        {
            Items = list.Select(MapToDto).ToList(),
            Page = page,
            PageSize = pageSize,
            TotalCount = total,
            EmptyStateMessage = total == 0 ? AppConstants.EmptyStateMessages.OrdersNone : null
        };

        var msg = total == 0 ? AppConstants.EmptyStateMessages.OrdersNone : "Orders loaded.";
        return ApiResponse<PagedListDto<OrderResponseDto>>.SuccessResult(pageDto, msg);
    }

    public async Task<ApiResponse<AnalyticsDto>> GetVendorAnalyticsAsync(string vendorId, int lastDays = 30)
    {
        var from = DateTime.UtcNow.Date.AddDays(-lastDays);
        var orders = await _context.Orders
            .Where(o => o.VendorId == vendorId && o.CreatedAt >= from && (o.Status == OrderStatus.Shipped || o.Status == OrderStatus.Completed))
            .ToListAsync();

        var byDay = orders
            .GroupBy(o => o.CreatedAt.Date)
            .Select(g => new SalesByDayDto { Date = g.Key, TotalSales = g.Sum(o => o.Amount), OrderCount = g.Count() })
            .OrderBy(x => x.Date)
            .ToList();

        var eventTypes = await _context.VendorTrafficEvents
            .AsNoTracking()
            .Where(e => e.VendorId == vendorId && e.CreatedAt >= from)
            .Select(e => e.EventType)
            .ToListAsync();

        var views = eventTypes.Count(e => e == VendorTrafficEventType.ProductView);
        var clickThrough = eventTypes.Count(e => e == VendorTrafficEventType.ClickThrough);
        var favourites = eventTypes.Count(e => e == VendorTrafficEventType.Favourite);
        var searches = eventTypes.Count(e => e == VendorTrafficEventType.Search);

        var result = new AnalyticsDto
        {
            Performance = byDay,
            Favourites = favourites,
            ClickThrough = clickThrough,
            Views = views,
            TotalSearches = searches,
            SalesInsight = byDay.Count == 0 ? AppConstants.EmptyStateMessages.AnalyticsNoSalesInPeriod : null,
            EngagementInsight = views + clickThrough + favourites + searches == 0
                ? AppConstants.EmptyStateMessages.AnalyticsNoEngagement
                : null
        };

        return ApiResponse<AnalyticsDto>.SuccessResult(result, "Analytics loaded.");
    }

    public async Task<ApiResponse<OrderResponseDto>> UpdateStatusAsync(string orderId, string vendorId, UpdateOrderStatusDto dto)
    {
        var order = await _context.Orders
            .Include(o => o.Product)
            .FirstOrDefaultAsync(o => o.Id == orderId && o.VendorId == vendorId);
        if (order == null)
            return ApiResponse<OrderResponseDto>.ErrorResult("Order not found.", ResponseCodes.NOT_FOUND);
        var prev = order.Status;
        order.Status = dto.Status;
        order.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
        if (order.Status == OrderStatus.Completed && prev != OrderStatus.Completed)
            await _notifications.NotifyOrderPaymentConfirmedAsync(order, order.Product?.Name);
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
            GuestEmail = o.GuestEmail,
            GuestName = o.GuestName,
            Amount = o.Amount,
            Status = o.Status.ToString(),
            ProductId = o.ProductId,
            ProductName = o.Product?.Name,
            CreatedAt = o.CreatedAt,
            UpdatedAt = o.UpdatedAt
        };
    }
}
