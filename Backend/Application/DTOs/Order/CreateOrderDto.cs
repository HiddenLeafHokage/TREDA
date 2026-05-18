using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Order;

public class CreateOrderDto
{
    /// <summary>Required when buyer is registered; omit for guest.</summary>
    public string? BuyerId { get; set; }

    public string? ProductId { get; set; }

    [Range(0, double.MaxValue)]
    public decimal Amount { get; set; }

    [MaxLength(200)]
    public string CustomerName { get; set; } = string.Empty;

    [MaxLength(256)]
    [EmailAddress]
    public string? GuestEmail { get; set; }

    [MaxLength(200)]
    public string? GuestName { get; set; }
}
