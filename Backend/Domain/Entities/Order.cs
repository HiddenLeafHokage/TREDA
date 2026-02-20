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

    [Required]
    public string BuyerId { get; set; } = string.Empty;
    public User? Buyer { get; set; }

    public string? ProductId { get; set; }
    public Product? Product { get; set; }

    /// <summary>Agreed value (e.g. N850,000) - for display only, no platform payment.</summary>
    [Range(0, double.MaxValue)]
    public decimal Amount { get; set; }

    public OrderStatus Status { get; set; } = OrderStatus.Pending;

    [MaxLength(200)]
    public string CustomerName { get; set; } = string.Empty; // Buyer display name

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
