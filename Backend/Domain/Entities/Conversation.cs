using System.ComponentModel.DataAnnotations;

namespace Domain.Entities;

/// <summary>Chat thread between a buyer and a vendor (optionally about a product).</summary>
public class Conversation
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string VendorId { get; set; } = string.Empty;
    public User? Vendor { get; set; }

    [Required]
    public string BuyerId { get; set; } = string.Empty;
    public User? Buyer { get; set; }

    public string? ProductId { get; set; }
    public Product? Product { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public virtual ICollection<Message> Messages { get; set; } = new List<Message>();
}
