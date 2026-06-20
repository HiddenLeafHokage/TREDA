using Application.DTOs.Common;
using Application.DTOs.Product;

namespace Application.DTOs.Vendor;

/// <summary>Public vendor storefront (buyer-facing shop page).</summary>
public class VendorPublicProfileDto
{
    public string Id { get; set; } = string.Empty;
    public string BusinessName { get; set; } = string.Empty;
    public string? BusinessCategory { get; set; }
    public List<string> BusinessCategoryIds { get; set; } = new();
    public string? BusinessLocation { get; set; }
    public string? ShopDescription { get; set; }
    public string? BusinessLogoUrl { get; set; }
    public string? BusinessCoverPhotoUrl { get; set; }
    public string DisplayInitial { get; set; } = "V";
    public PagedListDto<ProductResponseDto> Products { get; set; } = new();
}
