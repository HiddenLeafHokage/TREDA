namespace Application.DTOs.Vendor;

/// <summary>Branding-only update. Logo and cover photo changes are limited by cooldown.</summary>
public class UpdateVendorBrandingDto
{
    public string? BusinessLogoUrl { get; set; }
    public string? BusinessCoverPhotoUrl { get; set; }
}
