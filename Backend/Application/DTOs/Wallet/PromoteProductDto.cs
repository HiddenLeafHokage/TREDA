using System.ComponentModel.DataAnnotations;
using Application.Constants;

namespace Application.DTOs.Wallet;

/// <summary>Vendor pays Treda to promote a product (Treda Ads).</summary>
public class PromoteProductDto
{
    [Range(0.01, double.MaxValue, ErrorMessage = "Amount must be greater than 0")]
    public decimal Amount { get; set; }

    /// <summary>Promotion duration in days.</summary>
    [Range(AppConstants.MinPromotionDurationDays, AppConstants.MaxPromotionDurationDays)]
    public int DurationDays { get; set; } = AppConstants.DefaultPromotionDurationDays;
}
