using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Order;

public class CreateOrderDto
{
    [Required]
    public string BuyerId { get; set; } = string.Empty;

    public string? ProductId { get; set; }

    [Range(0, double.MaxValue)]
    public decimal Amount { get; set; }

    [MaxLength(200)]
    public string CustomerName { get; set; } = string.Empty;
}
