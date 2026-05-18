using System.ComponentModel.DataAnnotations;
using Domain.Enums;

namespace Domain.Entities;

public class VendorNotification
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string VendorId { get; set; } = string.Empty;
    public User? Vendor { get; set; }

    public NotificationCategory Category { get; set; }

    [MaxLength(200)]
    public string Title { get; set; } = string.Empty;

    [MaxLength(2000)]
    public string Body { get; set; } = string.Empty;

    public NotificationActionKind ActionKind { get; set; }

    public string? RelatedOrderId { get; set; }
    public string? RelatedConversationId { get; set; }
    public string? RelatedProductId { get; set; }

    public bool IsRead { get; set; }
    public DateTime? ReadAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
