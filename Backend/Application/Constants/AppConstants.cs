using Domain.Enums;

namespace Application.Constants;

/// <summary>Central place for magic numbers and display defaults. No hand-coded literals in services.</summary>
public static class AppConstants
{
    public const int MessagePreviewMaxLength = 50;
    public const string MessagePreviewSuffix = "...";
    public const string OrderIdDisplayPrefix = "#";
    public const int OrderIdDisplayLength = 4;
    public const string DefaultBuyerDisplayName = "Buyer";
    public const int DefaultPageSize = 20;
    public const int DefaultMessagePageSize = 50;
    public const int DefaultBestSellingLimit = 10;
    public const int DefaultPromotionDurationDays = 7;
    public const int MinPromotionDurationDays = 1;
    public const int MaxPromotionDurationDays = 365;

    /// <summary>Role names aligned with <see cref="UserType"/> enum. Vendor = Seller (same thing).</summary>
    public static class Roles
    {
        public const string Buyer = nameof(UserType.Buyer);
        public const string Vendor = nameof(UserType.Vendor);
        public const string Admin = nameof(UserType.Admin);
    }
}
