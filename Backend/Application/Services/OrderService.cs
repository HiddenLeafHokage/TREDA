using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Order;
using Application.DTOs.Vendor;
using Application.Interfaces;
using Application.Subscriptions;
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

    public async Task<ApiResponse<OrderResponseDto>> CreateGuestOrderAsync(CreateGuestOrderDto dto)
    {
        var vendor = await _context.Users
            .FirstOrDefaultAsync(u => u.Id == dto.VendorId && u.UserType == UserType.Vendor && u.IsActive);
        if (vendor == null)
            return ApiResponse<OrderResponseDto>.ErrorResult("Vendor not found.", ResponseCodes.NOT_FOUND);

        if (dto.Items == null || dto.Items.Count == 0)
            return ApiResponse<OrderResponseDto>.ErrorResult("At least one item is required.", ResponseCodes.VALIDATION_ERROR);

        // Load the products for this vendor and validate every requested item.
        var requestedIds = dto.Items.Select(i => i.ProductId).Distinct().ToList();
        var products = await _context.Products
            .Where(p => requestedIds.Contains(p.Id) && p.VendorId == dto.VendorId && p.IsActive)
            .ToDictionaryAsync(p => p.Id);

        var items = new List<OrderItem>();
        foreach (var line in dto.Items)
        {
            if (!products.TryGetValue(line.ProductId, out var product))
                return ApiResponse<OrderResponseDto>.ErrorResult(
                    $"Product '{line.ProductId}' is not available from this store.", ResponseCodes.VALIDATION_ERROR);
            if (line.Quantity < 1)
                return ApiResponse<OrderResponseDto>.ErrorResult("Quantity must be at least 1.", ResponseCodes.VALIDATION_ERROR);

            items.Add(new OrderItem
            {
                ProductId = product.Id,
                ProductName = product.Name,   // snapshot
                UnitPrice = product.Price,    // snapshot — never trust a price from the client
                Quantity = line.Quantity
            });
        }

        var subtotal = items.Sum(i => i.LineTotal);
        var order = new Order
        {
            Id = Guid.NewGuid().ToString(),
            VendorId = dto.VendorId,
            BuyerId = null,
            CustomerName = dto.GuestName,
            GuestName = dto.GuestName,
            GuestEmail = string.IsNullOrWhiteSpace(dto.GuestEmail) ? null : dto.GuestEmail.Trim(),
            GuestPhone = dto.GuestPhone,
            DeliveryAddress = dto.DeliveryAddress,
            DeliveryCity = dto.DeliveryCity,
            DeliveryState = dto.DeliveryState,
            DeliveryNote = dto.DeliveryNote,
            DeliveryMethod = vendor.DeliveryMethod,   // snapshot from the vendor's setting
            Items = items,
            Subtotal = subtotal,
            DeliveryFee = 0,
            Total = subtotal,
            Status = OrderStatus.Pending,
            PaymentStatus = PaymentStatus.AwaitingPayment,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        _context.Orders.Add(order);
        await _context.SaveChangesAsync();

        await _notifications.NotifyNewOrderAsync(order, ItemsSummary(order));
        return ApiResponse<OrderResponseDto>.SuccessResult(MapToDto(order), "Order placed. The seller will confirm shortly.");
    }

    public async Task<ApiResponse<OrderResponseDto>> GetByIdAsync(string orderId, string vendorId)
    {
        var order = await _context.Orders
            .Include(o => o.Items)
            .FirstOrDefaultAsync(o => o.Id == orderId && o.VendorId == vendorId);
        if (order == null)
            return ApiResponse<OrderResponseDto>.ErrorResult("Order not found.", ResponseCodes.NOT_FOUND);

        // Paywall: a limited (free) plan can only open its N most-recent pending orders.
        if (order.Status == OrderStatus.Pending)
        {
            var limit = await PendingViewLimitAsync(vendorId);
            if (limit != SubscriptionPlans.Unlimited)
            {
                var newerPending = await _context.Orders.CountAsync(o =>
                    o.VendorId == vendorId && o.Status == OrderStatus.Pending && o.CreatedAt > order.CreatedAt);
                if (newerPending >= limit)
                    return ApiResponse<OrderResponseDto>.ErrorResult(
                        $"This pending order is locked on your current plan (you can view {limit}). Subscribe to view all pending orders.",
                        ResponseCodes.FORBIDDEN);
            }
        }

        return ApiResponse<OrderResponseDto>.SuccessResult(MapToDto(order));
    }

    private async Task<int> PendingViewLimitAsync(string vendorId)
    {
        var vendor = await _context.Users.AsNoTracking().FirstAsync(u => u.Id == vendorId);
        return SubscriptionPlans.For(vendor).MaxPendingOrdersViewable;
    }

    public async Task<ApiResponse<List<OrderResponseDto>>> GetVendorOrdersAsync(string vendorId, DateTime? from, DateTime? to)
    {
        var query = _context.Orders.Include(o => o.Items).Where(o => o.VendorId == vendorId);
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

        var query = _context.Orders.Include(o => o.Items).Where(o => o.VendorId == vendorId);

        if (from.HasValue) query = query.Where(o => o.CreatedAt >= from.Value);
        if (to.HasValue) query = query.Where(o => o.CreatedAt <= to.Value);
        if (!string.IsNullOrWhiteSpace(search))
        {
            var q = search.Trim();
            query = query.Where(o =>
                o.CustomerName.Contains(q) ||
                (o.GuestPhone != null && o.GuestPhone.Contains(q)) ||
                (o.GuestEmail != null && o.GuestEmail.Contains(q)));
        }
        if (!string.IsNullOrWhiteSpace(status) && !string.Equals(status, "all", StringComparison.OrdinalIgnoreCase)
            && Enum.TryParse<OrderStatus>(status, true, out var st))
            query = query.Where(o => o.Status == st);

        // Paywall: a limited (free) plan can only view its N most-recent pending orders; the rest
        // are hidden from the list and surfaced as LockedCount so the UI can prompt "subscribe".
        var lockedPending = 0;
        var pendingLimit = await PendingViewLimitAsync(vendorId);
        if (pendingLimit != SubscriptionPlans.Unlimited)
        {
            var pendingIds = await _context.Orders
                .Where(o => o.VendorId == vendorId && o.Status == OrderStatus.Pending)
                .OrderByDescending(o => o.CreatedAt)
                .Select(o => o.Id)
                .ToListAsync();
            var visiblePendingIds = pendingIds.Take(pendingLimit).ToList();
            lockedPending = Math.Max(0, pendingIds.Count - pendingLimit);
            query = query.Where(o => o.Status != OrderStatus.Pending || visiblePendingIds.Contains(o.Id));
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
            EmptyStateMessage = total == 0 ? AppConstants.EmptyStateMessages.OrdersNone : null,
            LockedCount = lockedPending > 0 ? lockedPending : null
        };

        var msg = total == 0 ? AppConstants.EmptyStateMessages.OrdersNone : "Orders loaded.";
        return ApiResponse<PagedListDto<OrderResponseDto>>.SuccessResult(pageDto, msg);
    }

    public async Task<ApiResponse<OrderResponseDto>> UpdateOrderAsync(string orderId, string vendorId, UpdateOrderDto dto)
    {
        var order = await _context.Orders.Include(o => o.Items)
            .FirstOrDefaultAsync(o => o.Id == orderId && o.VendorId == vendorId);
        if (order == null)
            return ApiResponse<OrderResponseDto>.ErrorResult("Order not found.", ResponseCodes.NOT_FOUND);

        var prevStatus = order.Status;
        if (dto.DeliveryFee.HasValue)
        {
            order.DeliveryFee = dto.DeliveryFee.Value;
            order.Total = order.Subtotal + order.DeliveryFee;
        }
        if (dto.Status.HasValue) order.Status = dto.Status.Value;
        order.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        if (order.Status != prevStatus)
            await _notifications.NotifyOrderStatusChangedAsync(order, prevStatus);
        return ApiResponse<OrderResponseDto>.SuccessResult(MapToDto(order), "Order updated.");
    }

    public async Task<ApiResponse<OrderResponseDto>> UpdateStatusAsync(string orderId, string vendorId, UpdateOrderStatusDto dto)
    {
        var order = await _context.Orders.Include(o => o.Items)
            .FirstOrDefaultAsync(o => o.Id == orderId && o.VendorId == vendorId);
        if (order == null)
            return ApiResponse<OrderResponseDto>.ErrorResult("Order not found.", ResponseCodes.NOT_FOUND);

        var prev = order.Status;
        order.Status = dto.Status;
        order.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        if (order.Status != prev)
            await _notifications.NotifyOrderStatusChangedAsync(order, prev);
        return ApiResponse<OrderResponseDto>.SuccessResult(MapToDto(order), "Order status updated.");
    }

    public async Task<ApiResponse<OrderResponseDto>> UpdatePaymentStatusAsync(string orderId, string vendorId, UpdatePaymentStatusDto dto)
    {
        var order = await _context.Orders.Include(o => o.Items)
            .FirstOrDefaultAsync(o => o.Id == orderId && o.VendorId == vendorId);
        if (order == null)
            return ApiResponse<OrderResponseDto>.ErrorResult("Order not found.", ResponseCodes.NOT_FOUND);

        var previousPayment = order.PaymentStatus;
        order.PaymentStatus = dto.PaymentStatus;
        order.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        if (order.PaymentStatus == PaymentStatus.Paid && previousPayment != PaymentStatus.Paid)
            await _notifications.NotifyOrderPaymentConfirmedAsync(order, ItemsSummary(order));
        return ApiResponse<OrderResponseDto>.SuccessResult(MapToDto(order), "Payment status updated.");
    }

    public async Task<ApiResponse<InvoiceDto>> GetInvoiceAsync(string orderId, string vendorId)
    {
        var order = await _context.Orders
            .Include(o => o.Items)
            .Include(o => o.Vendor)
            .FirstOrDefaultAsync(o => o.Id == orderId && o.VendorId == vendorId);
        if (order == null)
            return ApiResponse<InvoiceDto>.ErrorResult("Order not found.", ResponseCodes.NOT_FOUND);

        var v = order.Vendor;
        var invoice = new InvoiceDto
        {
            OrderId = order.Id,
            OrderNumber = order.OrderNumber,
            InvoiceNumber = $"INV-{order.CreatedAt:yyyy}-{order.OrderNumber}",
            IssuedAt = order.CreatedAt,
            Status = order.Status.ToString(),
            PaymentStatus = order.PaymentStatus.ToString(),
            FromStoreName = v?.BusinessName ?? v?.FullName ?? "Store",
            FromPhone = v?.PhoneNumber,
            FromLocation = v?.BusinessLocation,
            ToName = order.CustomerName,
            ToPhone = order.GuestPhone,
            ToEmail = order.GuestEmail,
            DeliveryAddress = order.DeliveryAddress,
            DeliveryCity = order.DeliveryCity,
            DeliveryState = order.DeliveryState,
            Items = order.Items.Select(i => new OrderItemDto
            {
                ProductId = i.ProductId,
                ProductName = i.ProductName,
                UnitPrice = i.UnitPrice,
                Quantity = i.Quantity,
                LineTotal = i.LineTotal
            }).ToList(),
            Subtotal = order.Subtotal,
            DeliveryFee = order.DeliveryFee,
            Total = order.Total
        };
        return ApiResponse<InvoiceDto>.SuccessResult(invoice);
    }

    public async Task<ApiResponse<AnalyticsDto>> GetVendorAnalyticsAsync(string vendorId, int lastDays = 30)
    {
        var from = DateTime.UtcNow.Date.AddDays(-lastDays);
        var orders = await _context.Orders
            .Where(o => o.VendorId == vendorId && o.CreatedAt >= from && (o.Status == OrderStatus.Shipped || o.Status == OrderStatus.Completed))
            .ToListAsync();

        var byDay = orders
            .GroupBy(o => o.CreatedAt.Date)
            .Select(g => new SalesByDayDto { Date = g.Key, TotalSales = g.Sum(o => o.Total), OrderCount = g.Count() })
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

    private static string ItemsSummary(Order o)
    {
        var first = o.Items.FirstOrDefault()?.ProductName ?? "items";
        var extra = o.Items.Count - 1;
        return extra > 0 ? $"{first} (+{extra} more)" : first;
    }

    private static OrderResponseDto MapToDto(Order o)
    {
        return new OrderResponseDto
        {
            Id = o.Id,
            OrderNumber = o.OrderNumber,
            OrderIdDisplay = $"#{o.OrderNumber}",
            InvoiceNumber = $"INV-{o.CreatedAt:yyyy}-{o.OrderNumber}",
            CustomerName = o.CustomerName,
            GuestName = o.GuestName,
            GuestEmail = o.GuestEmail,
            GuestPhone = o.GuestPhone,
            DeliveryAddress = o.DeliveryAddress,
            DeliveryCity = o.DeliveryCity,
            DeliveryState = o.DeliveryState,
            DeliveryNote = o.DeliveryNote,
            DeliveryMethod = o.DeliveryMethod?.ToString(),
            Items = o.Items
                .Select(i => new OrderItemDto
                {
                    ProductId = i.ProductId,
                    ProductName = i.ProductName,
                    UnitPrice = i.UnitPrice,
                    Quantity = i.Quantity,
                    LineTotal = i.LineTotal
                })
                .ToList(),
            Subtotal = o.Subtotal,
            DeliveryFee = o.DeliveryFee,
            Total = o.Total,
            Status = o.Status.ToString(),
            PaymentStatus = o.PaymentStatus.ToString(),
            CreatedAt = o.CreatedAt,
            UpdatedAt = o.UpdatedAt
        };
    }
}
