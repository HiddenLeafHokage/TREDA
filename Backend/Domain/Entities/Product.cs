using System.ComponentModel.DataAnnotations;
using Domain.Enums;

namespace Domain.Entities;

public class Product
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string Description { get; set; } = string.Empty;

    [Range(0, double.MaxValue)]
    public decimal Price { get; set; }

    /// <summary>Optional sale price; must be lower than <see cref="Price"/> when set.</summary>
    [Range(0, double.MaxValue)]
    public decimal? DiscountPrice { get; set; }

    [Required]
    public string CategoryId { get; set; } = string.Empty;
    public ProductCategory? Category { get; set; }

    public ProductCondition Condition { get; set; } = ProductCondition.New;

    /// <summary>Draft products are invisible to buyers until explicitly published.</summary>
    public ProductStatus Status { get; set; } = ProductStatus.Published;

    [MaxLength(200)]
    public string? Location { get; set; } // City/area for pickup (Jiji-style)

    public List<string> ImageUrls { get; set; } = new();
    public int StockQuantity { get; set; }
    public bool IsActive { get; set; } = true;

    /// <summary>Featured/promoted (homepage Featured Products). Paid sellers only, capped per plan.</summary>
    public bool IsPromoted { get; set; }
    public DateTime? PromotedAt { get; set; }

    public string VendorId { get; set; } = string.Empty; // Vendor = Seller
    public User? Vendor { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
