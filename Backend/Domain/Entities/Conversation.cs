using System.ComponentModel.DataAnnotations;

namespace Domain.Entities;

/// <summary>Chat thread between a buyer and a vendor (optionally about a product).</summary>
public class Conversation
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string VendorId { get; set; } = string.Empty;
    public User? Vendor { get; set; }

    /// <summary>Set when buyer is registered; null for guest.</summary>
    public string? BuyerId { get; set; }
    public User? Buyer { get; set; }

    [MaxLength(256)]
    public string? GuestEmail { get; set; }

    [MaxLength(200)]
    public string? GuestName { get; set; }

    public string? ProductId { get; set; }
    public Product? Product { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public virtual ICollection<Message> Messages { get; set; } = new List<Message>();
}
