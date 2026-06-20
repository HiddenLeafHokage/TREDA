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
    public const int MaxProductImagesPerProduct = 5;
    public const int VendorBrandingChangeCooldownMonths = 6;

    /// <summary>User-facing copy when lists or charts have no data yet.</summary>
    public static class EmptyStateMessages
    {
        public const string AnalyticsNoSalesInPeriod =
            "No completed or shipped sales in this period yet. When buyers confirm orders, performance will appear here.";
        public const string DashboardNoRevenueYet =
            "No shipped or completed orders yet. Your total sales will appear here once you record those order statuses.";
        public const string AnalyticsNoEngagement =
            "No listing engagement recorded yet. Views are counted when buyers open a product; use POST /api/public/products/{{id}}/engage for clicks or favourites from your storefront.";
        public const string NotificationsNone = "No notifications yet. New orders, messages, wallet activity, and promotions will show up here.";
        public const string VendorSearchNoMatches = "No products, orders, or conversations matched your search.";
        public const string ProductsNone = "You have not added any products yet. Use POST /api/products to create your first listing.";
        public const string OrdersNone = "No orders yet. When buyers place inquiries, they will appear here.";
        public const string BestSellingNone = "No best-selling data yet. Sales appear after orders are marked Shipped or Completed.";
        public const string PublicProductsNone = "No active listings match your search or category yet.";
    }
}
