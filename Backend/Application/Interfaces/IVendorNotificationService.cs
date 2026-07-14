using Application.DTOs.Common;
using Application.DTOs.Notification;
using Domain.Entities;
using Domain.Enums;

namespace Application.Interfaces;

public interface IVendorNotificationService
{
    Task<ApiResponse<PagedListDto<VendorNotificationDto>>> GetPagedAsync(
        string vendorId, string? category, int page, int pageSize);

    Task<ApiResponse<NotificationSummaryDto>> GetSummaryAsync(string vendorId);
    Task<ApiResponse<bool>> MarkReadAsync(string vendorId, string notificationId);
    Task<ApiResponse<bool>> MarkAllReadAsync(string vendorId, string? category);

    Task NotifyNewOrderAsync(Order order, string? productName);

    /// <summary>Payment marked received (off-platform) for an order.</summary>
    Task NotifyOrderPaymentConfirmedAsync(Order order, string? productName);

    /// <summary>Fulfilment status moved (e.g. Pending → Shipped).</summary>
    Task NotifyOrderStatusChangedAsync(Order order, OrderStatus previousStatus);

    Task NotifyNewMessageFromBuyerAsync(string vendorId, string conversationId, string preview, string? senderName);

    /// <summary>A listing was promoted (featured) — included in the seller's plan.</summary>
    Task NotifyListingPromotedAsync(string vendorId, string productId, string productName);

    /// <summary>Subscription plan granted, changed, or cleared.</summary>
    Task NotifySubscriptionChangedAsync(string vendorId, SubscriptionTier tier, DateTime? expiresAt);
}
