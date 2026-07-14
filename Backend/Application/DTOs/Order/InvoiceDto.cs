namespace Application.DTOs.Order;

/// <summary>
/// Everything the frontend needs to render (and export as an image for WhatsApp) an invoice for an order.
/// The backend supplies the data; the frontend renders + exports the picture.
/// </summary>
public class InvoiceDto
{
    public string OrderId { get; set; } = string.Empty;
    public int OrderNumber { get; set; }
    public string InvoiceNumber { get; set; } = string.Empty;   // "INV-2026-1032"
    public DateTime IssuedAt { get; set; }
    public string Status { get; set; } = string.Empty;
    public string PaymentStatus { get; set; } = string.Empty;   // "AwaitingPayment" / "Paid"

    // Invoice From — the seller
    public string FromStoreName { get; set; } = string.Empty;
    public string? FromPhone { get; set; }
    public string? FromLocation { get; set; }

    // Invoice To — the buyer
    public string ToName { get; set; } = string.Empty;
    public string? ToPhone { get; set; }
    public string? ToEmail { get; set; }
    public string? DeliveryAddress { get; set; }
    public string? DeliveryCity { get; set; }
    public string? DeliveryState { get; set; }

    public List<OrderItemDto> Items { get; set; } = new();
    public decimal Subtotal { get; set; }
    public decimal DeliveryFee { get; set; }
    public decimal Total { get; set; }
}
