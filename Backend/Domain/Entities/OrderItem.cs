using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Domain.Entities;

/// <summary>
/// One line in an order. Name and price are SNAPSHOTTED at order time, so editing or deleting the
/// product later never rewrites order history. ProductId is kept only as a reference (no FK), so a
/// product can still be deleted without affecting past orders.
/// </summary>
public class OrderItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    public string OrderId { get; set; } = string.Empty;
    public Order Order { get; set; } = null!;

    public string ProductId { get; set; } = string.Empty;

    [MaxLength(200)]
    public string ProductName { get; set; } = string.Empty;

    public decimal UnitPrice { get; set; }
    public int Quantity { get; set; }

    [NotMapped]
    public decimal LineTotal => UnitPrice * Quantity;
}
