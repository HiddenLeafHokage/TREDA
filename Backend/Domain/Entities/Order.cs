using System.ComponentModel.DataAnnotations;
using Domain.Enums;

namespace Domain.Entities;

/// <summary>
/// Inquiry/lead from a buyer - no payment on platform. Vendor tracks deal status (e.g. agreed amount, Shipped).
/// </summary>
public class Order
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string VendorId { get; set; } = string.Empty;
    public User? Vendor { get; set; }

    /// <summary>Set when buyer is registered; null for guest.</summary>
    public string? BuyerId { get; set; }
    public User? Buyer { get; set; }

    /// <summary>Guest buyer email (when BuyerId is null).</summary>
    [MaxLength(256)]
    public string? GuestEmail { get; set; }

    [MaxLength(200)]
    public string? GuestName { get; set; }

    public string? ProductId { get; set; }
    public Product? Product { get; set; }

    /// <summary>Agreed / proposed amount (invoice); seller can edit to negotiate.</summary>
    [Range(0, double.MaxValue)]
    public decimal Amount { get; set; }

    public OrderStatus Status { get; set; } = OrderStatus.Pending;

    [MaxLength(200)]
    public string CustomerName { get; set; } = string.Empty; // Buyer or guest display name

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
