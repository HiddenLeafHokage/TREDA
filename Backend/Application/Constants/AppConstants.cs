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

    /// <summary>Email verification code expiry (minutes). After this, user must request a new code.</summary>
    public const int EmailVerificationExpiryMinutes = 45;

    /// <summary>Role names aligned with <see cref="UserType"/> enum. Vendor = Seller (same thing).</summary>
    public static class Roles
    {
        public const string Buyer = nameof(UserType.Buyer);
        public const string Vendor = nameof(UserType.Vendor);
        public const string Admin = nameof(UserType.Admin);
    }

    /// <summary>Phone: accept +234..., 090..., 0..., etc. One number per account.</summary>
    public const string PhoneNumberPattern = @"^\+?[\d\s\-]{10,20}$";

    /// <summary>Allowed file extensions for uploads (images + PDF).</summary>
    public static readonly string[] AllowedUploadExtensions = { ".jpg", ".jpeg", ".png", ".gif", ".webp", ".pdf" };
    public const int MaxUploadSizeBytes = 5 * 1024 * 1024; // 5 MB
}
