using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Order;

/// <summary>Vendor can update status and/or amount (negotiate invoice).</summary>
public class UpdateOrderDto
{
    public Domain.Enums.OrderStatus? Status { get; set; }

    [Range(0, double.MaxValue)]
    public decimal? Amount { get; set; }
}
