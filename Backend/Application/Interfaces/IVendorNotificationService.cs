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
    Task NotifyOrderPaymentConfirmedAsync(Order order, string? productName);
    Task NotifyNewMessageFromBuyerAsync(string vendorId, string conversationId, string preview, string? senderName);
    Task NotifyListingPromotedAsync(string vendorId, string productId, string productName, decimal amountPaid);
}
