using Domain.Enums;

namespace Application.DTOs.Order;

public class OrderResponseDto
{
    public string Id { get; set; } = string.Empty;
    public string OrderIdDisplay { get; set; } = string.Empty; // e.g. "#1032"
    public string CustomerName { get; set; } = string.Empty;
    public string? GuestEmail { get; set; }
    public string? GuestName { get; set; }
    public decimal Amount { get; set; }
    public string Status { get; set; } = string.Empty;
    public string? ProductId { get; set; }
    public string? ProductName { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
