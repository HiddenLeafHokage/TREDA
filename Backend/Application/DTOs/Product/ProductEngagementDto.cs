using System.ComponentModel.DataAnnotations;
using Domain.Enums;

namespace Application.DTOs.Product;

/// <summary>Anonymous engagement for analytics (optional; product views are also recorded on GET product detail).</summary>
public class ProductEngagementDto
{
    [Required]
    public VendorTrafficEventType EventType { get; set; }
}
