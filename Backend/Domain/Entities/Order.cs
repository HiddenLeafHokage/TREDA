using System.ComponentModel.DataAnnotations;
using Domain.Enums;

namespace Domain.Entities;

/// <summary>
/// A buyer's order to ONE vendor (the cart is split per store, so one order = one store).
/// No payment on the platform — the vendor tracks fulfilment (<see cref="Status"/>) and marks
/// money received off-platform (<see cref="PaymentStatus"/>). Line items live in <see cref="Items"/>.
/// </summary>
public class Order
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>Human-friendly sequential number shown as #1234 (DB-generated identity).</summary>
    public int OrderNumber { get; set; }

    [Required]
    public string VendorId { get; set; } = string.Empty;
    public User? Vendor { get; set; }

    /// <summary>Set when the buyer is a registered user; null for guests (guests only, for now).</summary>
    public string? BuyerId { get; set; }
    public User? Buyer { get; set; }

    // ── Buyer contact (captured at checkout) ────────────────────────────────
    [MaxLength(200)] public string CustomerName { get; set; } = string.Empty;
    [MaxLength(200)] public string? GuestName { get; set; }
    [MaxLength(256)] public string? GuestEmail { get; set; }
    [MaxLength(40)]  public string? GuestPhone { get; set; }

    // ── Delivery (captured at checkout) ─────────────────────────────────────
    [MaxLength(500)] public string? DeliveryAddress { get; set; }
    [MaxLength(120)] public string? DeliveryCity { get; set; }
    [MaxLength(120)] public string? DeliveryState { get; set; }
    [MaxLength(500)] public string? DeliveryNote { get; set; }
    /// <summary>Snapshot of the vendor's delivery method at order time.</summary>
    public DeliveryMethod? DeliveryMethod { get; set; }

    // ── Money (Total = Subtotal + DeliveryFee, kept in sync) ────────────────
    public decimal Subtotal { get; set; }
    public decimal DeliveryFee { get; set; }
    public decimal Total { get; set; }

    public OrderStatus Status { get; set; } = OrderStatus.Pending;
    public PaymentStatus PaymentStatus { get; set; } = PaymentStatus.AwaitingPayment;

    public ICollection<OrderItem> Items { get; set; } = new List<OrderItem>();

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
