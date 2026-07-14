namespace Application.DTOs.Order;

/// <summary>Vendor marks the order as Paid / AwaitingPayment (payment happens off-platform).</summary>
public class UpdatePaymentStatusDto
{
    public Domain.Enums.PaymentStatus PaymentStatus { get; set; }
}
