namespace Domain.Enums;

/// <summary>
/// Payment happens OFF the platform (WhatsApp/transfer/etc). The vendor marks money as
/// received manually, so this is independent of the order's fulfilment <see cref="OrderStatus"/>.
/// </summary>
public enum PaymentStatus
{
    AwaitingPayment = 0,
    Paid = 1
}
