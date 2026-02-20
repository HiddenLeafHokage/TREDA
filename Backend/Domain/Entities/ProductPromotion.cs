using System.ComponentModel.DataAnnotations;

namespace Domain.Entities;

/// <summary>Vendor paid Treda to promote a product (Treda Ads).</summary>
public class ProductPromotion
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string ProductId { get; set; } = string.Empty;
    public Product? Product { get; set; }

    [Required]
    public string VendorId { get; set; } = string.Empty;

    [Range(0, double.MaxValue)]
    public decimal AmountPaid { get; set; }

    public DateTime StartDate { get; set; }
    public DateTime EndDate { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
