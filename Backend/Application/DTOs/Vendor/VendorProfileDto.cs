using Domain.Enums;

namespace Application.DTOs.Vendor;

public class VendorProfileDto
{
    public string Id { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? PhoneNumber { get; set; }
    public string? BusinessName { get; set; }
    public string? BusinessSlug { get; set; }
    public string? BusinessCategory { get; set; }
    public List<string> BusinessCategoryIds { get; set; } = new();
    public string? BusinessLocation { get; set; }
    public string? ShopDescription { get; set; }
    public string? BusinessLogoUrl { get; set; }
    public string? BusinessCoverPhotoUrl { get; set; }
    public VendorBrandingDto Branding { get; set; } = new();
    public string? CAC_RC_Number { get; set; }
    public DeliveryMethod? DeliveryMethod { get; set; }
    public bool EmailVerified { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
