namespace Application.DTOs.Order;

public class OrderResponseDto
{
    public string Id { get; set; } = string.Empty;
    public int OrderNumber { get; set; }
    public string OrderIdDisplay { get; set; } = string.Empty;   // e.g. "#1032"
    public string InvoiceNumber { get; set; } = string.Empty;    // e.g. "INV-2026-1032"

    public string CustomerName { get; set; } = string.Empty;
    public string? GuestName { get; set; }
    public string? GuestEmail { get; set; }
    public string? GuestPhone { get; set; }

    public string? DeliveryAddress { get; set; }
    public string? DeliveryCity { get; set; }
    public string? DeliveryState { get; set; }
    public string? DeliveryNote { get; set; }
    public string? DeliveryMethod { get; set; }

    public List<OrderItemDto> Items { get; set; } = new();

    public decimal Subtotal { get; set; }
    public decimal DeliveryFee { get; set; }
    public decimal Total { get; set; }

    public string Status { get; set; } = string.Empty;
    public string PaymentStatus { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public class OrderItemDto
{
    public string ProductId { get; set; } = string.Empty;
    public string ProductName { get; set; } = string.Empty;
    public decimal UnitPrice { get; set; }
    public int Quantity { get; set; }
    public decimal LineTotal { get; set; }
}
