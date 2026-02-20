using System.ComponentModel.DataAnnotations;

namespace Domain.Entities;

public class Message
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string ConversationId { get; set; } = string.Empty;
    public Conversation? Conversation { get; set; }

    [Required]
    public string SenderId { get; set; } = string.Empty; // User who sent (buyer or vendor)
    public User? Sender { get; set; }

    [Required]
    [MaxLength(2000)]
    public string Content { get; set; } = string.Empty;

    public DateTime SentAt { get; set; } = DateTime.UtcNow;
    public DateTime? ReadAt { get; set; }
}
