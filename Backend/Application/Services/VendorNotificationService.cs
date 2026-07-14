using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Notification;
using Application.Interfaces;
using Domain.Entities;
using Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Persistence.Data;

namespace Application.Services;

public class VendorNotificationService : IVendorNotificationService
{
    private readonly TredaDbContext _context;
    private readonly ILogger<VendorNotificationService> _logger;

    public VendorNotificationService(TredaDbContext context, ILogger<VendorNotificationService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<ApiResponse<PagedListDto<VendorNotificationDto>>> GetPagedAsync(
        string vendorId, string? category, int page, int pageSize)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 100);

        var query = _context.VendorNotifications.AsNoTracking().Where(n => n.VendorId == vendorId);
        if (!string.IsNullOrWhiteSpace(category) && !string.Equals(category, "all", StringComparison.OrdinalIgnoreCase))
        {
            if (Enum.TryParse<NotificationCategory>(category, true, out var cat))
                query = query.Where(n => n.Category == cat);
        }

        var total = await query.CountAsync();
        var items = await query
            .OrderByDescending(n => n.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(n => new VendorNotificationDto
            {
                Id = n.Id,
                Category = n.Category.ToString(),
                Title = n.Title,
                Body = n.Body,
                ActionKind = n.ActionKind.ToString(),
                RelatedOrderId = n.RelatedOrderId,
                RelatedConversationId = n.RelatedConversationId,
                RelatedProductId = n.RelatedProductId,
                IsRead = n.IsRead,
                ReadAt = n.ReadAt,
                CreatedAt = n.CreatedAt
            })
            .ToListAsync();

        var pageDto = new PagedListDto<VendorNotificationDto>
        {
            Items = items,
            Page = page,
            PageSize = pageSize,
            TotalCount = total,
            EmptyStateMessage = total == 0 ? AppConstants.EmptyStateMessages.NotificationsNone : null
        };

        var msg = total == 0
            ? AppConstants.EmptyStateMessages.NotificationsNone
            : "Notifications loaded.";
        return ApiResponse<PagedListDto<VendorNotificationDto>>.SuccessResult(pageDto, msg);
    }

    public async Task<ApiResponse<NotificationSummaryDto>> GetSummaryAsync(string vendorId)
    {
        var baseQuery = _context.VendorNotifications.Where(n => n.VendorId == vendorId);
        var unread = baseQuery.Where(n => !n.IsRead);

        var dto = new NotificationSummaryDto
        {
            UnreadTotal = await unread.CountAsync(),
            UnreadOrders = await unread.CountAsync(n => n.Category == NotificationCategory.Order),
            UnreadPayments = await unread.CountAsync(n => n.Category == NotificationCategory.Payment),
            UnreadMessages = await unread.CountAsync(n => n.Category == NotificationCategory.Message),
            UnreadPromotions = await unread.CountAsync(n => n.Category == NotificationCategory.Promotion),
            EmptyStateMessage = await baseQuery.AnyAsync() ? null : AppConstants.EmptyStateMessages.NotificationsNone
        };

        return ApiResponse<NotificationSummaryDto>.SuccessResult(dto);
    }

    public async Task<ApiResponse<bool>> MarkReadAsync(string vendorId, string notificationId)
    {
        var n = await _context.VendorNotifications.FirstOrDefaultAsync(x => x.Id == notificationId && x.VendorId == vendorId);
        if (n == null)
            return ApiResponse<bool>.ErrorResult("Notification not found.", ResponseCodes.NOT_FOUND);
        if (!n.IsRead)
        {
            n.IsRead = true;
            n.ReadAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
        }
        return ApiResponse<bool>.SuccessResult(true, "Marked as read.");
    }

    public async Task<ApiResponse<bool>> MarkAllReadAsync(string vendorId, string? category)
    {
        var query = _context.VendorNotifications.Where(n => n.VendorId == vendorId && !n.IsRead);
        if (!string.IsNullOrWhiteSpace(category) && !string.Equals(category, "all", StringComparison.OrdinalIgnoreCase))
        {
            if (Enum.TryParse<NotificationCategory>(category, true, out var cat))
                query = query.Where(n => n.Category == cat);
        }

        var now = DateTime.UtcNow;
        await query.ExecuteUpdateAsync(s => s
            .SetProperty(n => n.IsRead, true)
            .SetProperty(n => n.ReadAt, now));

        return ApiResponse<bool>.SuccessResult(true, "All matching notifications marked as read.");
    }

    public async Task NotifyNewOrderAsync(Order order, string? productName)
    {
        try
        {
            var productPart = string.IsNullOrWhiteSpace(productName) ? "an item" : productName;
            var n = new VendorNotification
            {
                VendorId = order.VendorId,
                Category = NotificationCategory.Order,
                Title = "New order received",
                Body = $"{order.CustomerName} placed an order for {productPart} — ₦{order.Total:N0}.",
                ActionKind = NotificationActionKind.ViewOrder,
                RelatedOrderId = order.Id,
                RelatedProductId = order.Items.FirstOrDefault()?.ProductId,
                IsRead = false,
                CreatedAt = DateTime.UtcNow
            };
            _context.VendorNotifications.Add(n);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create order notification for vendor {VendorId}", order.VendorId);
        }
    }

    public async Task NotifyOrderPaymentConfirmedAsync(Order order, string? productName)
    {
        try
        {
            var productPart = string.IsNullOrWhiteSpace(productName) ? "your listing" : productName;
            var n = new VendorNotification
            {
                VendorId = order.VendorId,
                Category = NotificationCategory.Payment,
                Title = "Order marked completed",
                Body = $"₦{order.Total:N0} for order involving {productPart} is recorded as completed. Check your wallet and orders.",
                ActionKind = NotificationActionKind.ViewWallet,
                RelatedOrderId = order.Id,
                RelatedProductId = order.Items.FirstOrDefault()?.ProductId,
                IsRead = false,
                CreatedAt = DateTime.UtcNow
            };
            _context.VendorNotifications.Add(n);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create payment notification for vendor {VendorId}", order.VendorId);
        }
    }

    public async Task NotifyNewMessageFromBuyerAsync(string vendorId, string conversationId, string preview, string? senderName)
    {
        try
        {
            var who = string.IsNullOrWhiteSpace(senderName) ? "A buyer" : senderName;
            var n = new VendorNotification
            {
                VendorId = vendorId,
                Category = NotificationCategory.Message,
                Title = "New message",
                Body = $"{who}: {preview}",
                ActionKind = NotificationActionKind.ViewMessage,
                RelatedConversationId = conversationId,
                IsRead = false,
                CreatedAt = DateTime.UtcNow
            };
            _context.VendorNotifications.Add(n);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create message notification for vendor {VendorId}", vendorId);
        }
    }

    public async Task NotifyOrderStatusChangedAsync(Order order, OrderStatus previousStatus)
    {
        try
        {
            var n = new VendorNotification
            {
                VendorId = order.VendorId,
                Category = NotificationCategory.Order,
                Title = $"Order #{order.OrderNumber} {order.Status}",
                Body = $"Order #{order.OrderNumber} for {order.CustomerName} moved from {previousStatus} to {order.Status}.",
                ActionKind = NotificationActionKind.ViewOrder,
                RelatedOrderId = order.Id,
                RelatedProductId = order.Items.FirstOrDefault()?.ProductId,
                IsRead = false,
                CreatedAt = DateTime.UtcNow
            };
            _context.VendorNotifications.Add(n);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create order-status notification for vendor {VendorId}", order.VendorId);
        }
    }

    public async Task NotifyListingPromotedAsync(string vendorId, string productId, string productName)
    {
        try
        {
            var n = new VendorNotification
            {
                VendorId = vendorId,
                Category = NotificationCategory.Promotion,
                Title = "Listing promoted",
                Body = $"“{productName}” is now featured on the Treda homepage.",
                ActionKind = NotificationActionKind.ViewPromotion,
                RelatedProductId = productId,
                IsRead = false,
                CreatedAt = DateTime.UtcNow
            };
            _context.VendorNotifications.Add(n);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create promotion notification for vendor {VendorId}", vendorId);
        }
    }

    public async Task NotifySubscriptionChangedAsync(string vendorId, SubscriptionTier tier, DateTime? expiresAt)
    {
        try
        {
            var isFree = tier == SubscriptionTier.Free;
            var n = new VendorNotification
            {
                VendorId = vendorId,
                Category = NotificationCategory.Promotion,
                Title = isFree ? "Plan ended" : $"{tier} plan active",
                Body = isFree
                    ? "Your plan is now Free. Product and pending-order limits apply, and your store is no longer featured."
                    : $"Your {tier} plan is active until {expiresAt:yyyy-MM-dd}. Unlimited products, promotions, and featured placement are unlocked.",
                ActionKind = NotificationActionKind.ViewPromotion,
                IsRead = false,
                CreatedAt = DateTime.UtcNow
            };
            _context.VendorNotifications.Add(n);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create subscription notification for vendor {VendorId}", vendorId);
        }
    }
}
