namespace Application.DTOs.Notification;

/// <summary>Counts for notification bell / summary widget.</summary>
public class NotificationSummaryDto
{
    public int UnreadTotal { get; set; }
    public int UnreadOrders { get; set; }
    public int UnreadPayments { get; set; }
    public int UnreadMessages { get; set; }
    public int UnreadPromotions { get; set; }
    public string? EmptyStateMessage { get; set; }
}
