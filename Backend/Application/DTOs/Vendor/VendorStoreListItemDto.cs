namespace Application.DTOs.Vendor;

/// <summary>Public shop card for buyer-facing store listing.</summary>
public class VendorStoreListItemDto
{
    public string Id { get; set; } = string.Empty;
    public string Slug { get; set; } = string.Empty;
    public string BusinessName { get; set; } = string.Empty;
    public string? BusinessCategory { get; set; }
    public List<string> BusinessCategoryIds { get; set; } = new();
    public string? BusinessLocation { get; set; }
    public string? BusinessLogoUrl { get; set; }
    public string? BusinessCoverPhotoUrl { get; set; }
    public string DisplayInitial { get; set; } = "V";
    public int ProductCount { get; set; }
    public decimal Rating { get; set; }
    public int ReviewCount { get; set; }
}
