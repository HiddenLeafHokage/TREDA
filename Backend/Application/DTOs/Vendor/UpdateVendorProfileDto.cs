using System.ComponentModel.DataAnnotations;
using Domain.Enums;

namespace Application.DTOs.Vendor;

public class UpdateVendorProfileDto : IValidatableObject
{
    public string BusinessCategory { get; set; } = string.Empty;

    [MinLength(1, ErrorMessage = "Select at least one business category")]
    public List<string> BusinessCategoryIds { get; set; } = new();

    [Required(ErrorMessage = "Business location is required")]
    public string BusinessLocation { get; set; } = string.Empty;

    [Required(ErrorMessage = "Shop description is required")]
    [MaxLength(1000, ErrorMessage = "Shop description cannot exceed 1000 characters")]
    public string ShopDescription { get; set; } = string.Empty;

    public string? BusinessLogoUrl { get; set; }

    /// <summary>Shop cover/banner image URL (optional). Subject to 6-month change cooldown after first set.</summary>
    public string? BusinessCoverPhotoUrl { get; set; }

    [RegularExpression(@"^\+?[\d\s\-]{10,20}$", ErrorMessage = "Use a valid format e.g. +2348012345678 or 09012345678")]
    public string? PhoneNumber { get; set; }

    [Required(ErrorMessage = "Delivery method is required")]
    public DeliveryMethod DeliveryMethod { get; set; }

    [Required(ErrorMessage = "CAC/RC Number is required")]
    [RegularExpression(@"(?i)^(RC|CAC|BN|LLP|LP|IT)-\d{1,7}$", ErrorMessage = "CAC/RC Number must be in format: RC-1234567, CAC-1234567, BN-1234567, LLP-1234567, LP-1234567, or IT-1234567")]
    public string CAC_RC_Number { get; set; } = string.Empty;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (BusinessCategoryIds == null || BusinessCategoryIds.All(string.IsNullOrWhiteSpace))
        {
            yield return new ValidationResult(
                "Select at least one business category",
                new[] { nameof(BusinessCategoryIds) });
        }
    }
}
