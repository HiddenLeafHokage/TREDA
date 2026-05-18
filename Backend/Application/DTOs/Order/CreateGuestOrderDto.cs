using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Order;

/// <summary>Create order/inquiry as guest (no registration).</summary>
public class CreateGuestOrderDto
{
    [Required]
    public string VendorId { get; set; } = string.Empty;

    public string? ProductId { get; set; }

    [Required]
    [MaxLength(200)]
    public string GuestName { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    [MaxLength(256)]
    public string GuestEmail { get; set; } = string.Empty;

    [Range(0, double.MaxValue)]
    public decimal Amount { get; set; }

    [MaxLength(500)]
    public string? Message { get; set; }
}
