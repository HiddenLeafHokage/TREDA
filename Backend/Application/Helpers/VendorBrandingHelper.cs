using Application.Constants;
using Application.DTOs.Vendor;
using Domain.Entities;

namespace Application.Helpers;

public static class VendorBrandingHelper
{
    public static string GetDisplayInitial(User user)
    {
        var source = user.BusinessName?.Trim();
        if (string.IsNullOrEmpty(source))
            source = user.FullName?.Trim();
        if (string.IsNullOrEmpty(source))
            return "V";
        return char.ToUpperInvariant(source[0]).ToString();
    }

    public static DateTime? GetChangeAllowedAfter(DateTime? lastChangedAt)
    {
        if (!lastChangedAt.HasValue)
            return null;

        var allowed = lastChangedAt.Value.AddMonths(AppConstants.VendorBrandingChangeCooldownMonths);
        return DateTime.UtcNow >= allowed ? null : allowed;
    }

    public static VendorBrandingDto MapBranding(User user)
    {
        return new VendorBrandingDto
        {
            BusinessLogoUrl = user.BusinessLogoUrl,
            BusinessCoverPhotoUrl = user.BusinessCoverPhotoUrl,
            LogoLastChangedAt = user.BusinessLogoUpdatedAt,
            CoverPhotoLastChangedAt = user.BusinessCoverPhotoUpdatedAt,
            LogoChangeAllowedAfter = GetChangeAllowedAfter(user.BusinessLogoUpdatedAt),
            CoverPhotoChangeAllowedAfter = GetChangeAllowedAfter(user.BusinessCoverPhotoUpdatedAt),
            DisplayInitial = GetDisplayInitial(user)
        };
    }

    public static string? ValidateBrandingImageUrl(string? url, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(url))
            return null;

        var trimmed = url.Trim();
        if (trimmed.StartsWith("blob:", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
        {
            return $"{fieldName} must be uploaded with POST /api/upload first, then save the returned data.url.";
        }

        if (trimmed.StartsWith("/uploads/", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("uploads/", StringComparison.OrdinalIgnoreCase))
            return null;

        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var parsed) &&
            (parsed.Scheme == Uri.UriSchemeHttp || parsed.Scheme == Uri.UriSchemeHttps))
            return null;

        return $"Invalid {fieldName} URL. Upload with POST /api/upload and use the returned data.url.";
    }
}
