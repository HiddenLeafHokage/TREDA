namespace Domain.Enums;

/// <summary>Primary action CTA for the notification (frontend routing).</summary>
public enum NotificationActionKind
{
    None = 0,
    ViewOrder = 1,
    ViewWallet = 2,
    ViewMessage = 3,
    ViewPromotion = 4
}
