namespace Application.DTOs.Product;

/// <summary>Product plus seller/vendor contact info for buyers (no auth).</summary>
public class ProductWithVendorDto : ProductResponseDto
{
    public string? VendorName { get; set; }
    public string? VendorEmail { get; set; }
    public string? VendorPhone { get; set; }
    public string? BusinessName { get; set; }
    public string? BusinessLocation { get; set; }
    public string? BusinessLogoUrl { get; set; }
    public string? BusinessCoverPhotoUrl { get; set; }
    public string DisplayInitial { get; set; } = "V";
}
