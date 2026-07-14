using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Subscription;

/// <summary>Admin (test) lever: grant a vendor a plan without a real payment.</summary>
public class SetSubscriptionDto
{
    [Required]
    [EmailAddress]
    public string VendorEmail { get; set; } = string.Empty;

    /// <summary>Free | Silver | Gold | Premium. "Free" cancels/expires the plan.</summary>
    [Required]
    public string Tier { get; set; } = "Free";

    [Range(1, 3650)]
    public int DurationDays { get; set; } = 30;
}
