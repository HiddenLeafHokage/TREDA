namespace Application.DTOs.Message;

public class MessageDto
{
    public string Id { get; set; } = string.Empty;
    public string ConversationId { get; set; } = string.Empty;
    public string? SenderId { get; set; }
    public string? SenderDisplayName { get; set; } // User name or guest name
    public string Content { get; set; } = string.Empty;
    public DateTime SentAt { get; set; }
    public bool IsFromCurrentUser { get; set; }
}
