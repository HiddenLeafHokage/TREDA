namespace Application.DTOs.Vendor;

public class VendorBrandingDto
{
    public string? BusinessLogoUrl { get; set; }
    public string? BusinessCoverPhotoUrl { get; set; }
    public DateTime? LogoLastChangedAt { get; set; }
    public DateTime? CoverPhotoLastChangedAt { get; set; }

    /// <summary>When the vendor may change the logo again. Null means they can change it now.</summary>
    public DateTime? LogoChangeAllowedAfter { get; set; }

    /// <summary>When the vendor may change the cover photo again. Null means they can change it now.</summary>
    public DateTime? CoverPhotoChangeAllowedAfter { get; set; }

    /// <summary>First letter for default avatar when logo is not set (frontend fallback).</summary>
    public string DisplayInitial { get; set; } = "V";
}
