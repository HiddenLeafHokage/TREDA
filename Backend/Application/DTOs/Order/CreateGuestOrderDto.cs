using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Order;

/// <summary>Guest checkout to ONE store: one order, one or more line items (no registration).</summary>
public class CreateGuestOrderDto
{
    [Required]
    public string VendorId { get; set; } = string.Empty;

    [MinLength(1, ErrorMessage = "At least one item is required.")]
    public List<OrderItemInputDto> Items { get; set; } = new();

    [Required]
    [MaxLength(200)]
    public string GuestName { get; set; } = string.Empty;

    [Required]
    [MaxLength(40)]
    public string GuestPhone { get; set; } = string.Empty;

    [EmailAddress]
    [MaxLength(256)]
    public string? GuestEmail { get; set; }

    [Required]
    [MaxLength(500)]
    public string DeliveryAddress { get; set; } = string.Empty;

    [Required]
    [MaxLength(120)]
    public string DeliveryCity { get; set; } = string.Empty;

    [Required]
    [MaxLength(120)]
    public string DeliveryState { get; set; } = string.Empty;

    [MaxLength(500)]
    public string? DeliveryNote { get; set; }
}

/// <summary>One item the buyer is ordering. Price is taken from the product server-side, never trusted from the client.</summary>
public class OrderItemInputDto
{
    [Required]
    public string ProductId { get; set; } = string.Empty;

    [Range(1, 1000, ErrorMessage = "Quantity must be between 1 and 1000.")]
    public int Quantity { get; set; } = 1;
}
