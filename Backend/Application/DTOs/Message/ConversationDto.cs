namespace Application.DTOs.Message;

public class ConversationDto
{
    public string Id { get; set; } = string.Empty;
    public string? BuyerId { get; set; }
    public string BuyerName { get; set; } = string.Empty; // Registered buyer name or guest name
    public string? GuestEmail { get; set; }
    public string? ProductId { get; set; }
    public string? ProductName { get; set; }
    public string? LastMessagePreview { get; set; }
    public DateTime? LastMessageAt { get; set; }
    public int UnreadCount { get; set; }
}
