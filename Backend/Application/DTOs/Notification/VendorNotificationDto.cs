namespace Application.DTOs.Notification;

public class VendorNotificationDto
{
    public string Id { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Body { get; set; } = string.Empty;
    public string ActionKind { get; set; } = string.Empty;
    public string? RelatedOrderId { get; set; }
    public string? RelatedConversationId { get; set; }
    public string? RelatedProductId { get; set; }
    public bool IsRead { get; set; }
    public DateTime? ReadAt { get; set; }
    public DateTime CreatedAt { get; set; }
}
