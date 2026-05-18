using System.ComponentModel.DataAnnotations;

namespace Domain.Entities;

public class Message
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string ConversationId { get; set; } = string.Empty;
    public Conversation? Conversation { get; set; }

    /// <summary>User who sent (vendor or registered buyer); null when sent by guest.</summary>
    public string? SenderId { get; set; }
    public User? Sender { get; set; }

    [MaxLength(256)]
    public string? GuestSenderEmail { get; set; }

    [MaxLength(200)]
    public string? GuestSenderName { get; set; }

    [Required]
    [MaxLength(2000)]
    public string Content { get; set; } = string.Empty;

    public DateTime SentAt { get; set; } = DateTime.UtcNow;
    public DateTime? ReadAt { get; set; }
}
