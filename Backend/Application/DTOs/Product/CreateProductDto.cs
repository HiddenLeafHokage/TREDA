using System.ComponentModel.DataAnnotations;
using Domain.Enums;

namespace Application.DTOs.Product;

public class CreateProductDto
{
    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string Description { get; set; } = string.Empty;

    [Range(0, double.MaxValue)]
    public decimal Price { get; set; }

    [Required]
    public string CategoryId { get; set; } = string.Empty; // From GET /api/categories (e.g. cat-phones, cat-electronics)

    public ProductCondition Condition { get; set; } = ProductCondition.New; // 0=New, 1=Used, 2=Refurbished

    [MaxLength(200)]
    public string? Location { get; set; } // City/area for pickup (Jiji-style)

    public List<string> ImageUrls { get; set; } = new();

    [Range(0, int.MaxValue)]
    public int StockQuantity { get; set; }

    public bool IsActive { get; set; } = true;
}
