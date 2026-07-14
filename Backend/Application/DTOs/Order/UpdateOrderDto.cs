using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Order;

/// <summary>Vendor updates the order: set/adjust the delivery fee and/or the fulfilment status.</summary>
public class UpdateOrderDto
{
    public Domain.Enums.OrderStatus? Status { get; set; }

    /// <summary>Optional delivery fee the vendor adds. Total is recomputed as Subtotal + DeliveryFee.</summary>
    [Range(0, double.MaxValue)]
    public decimal? DeliveryFee { get; set; }
}
