using System.ComponentModel.DataAnnotations;
using Domain.Enums;

namespace Application.DTOs.Product;

public class UpdateProductDto
{
    [MaxLength(200)]
    public string? Name { get; set; }

    [MaxLength(1000)]
    public string? Description { get; set; }

    [Range(0, double.MaxValue)]
    public decimal? Price { get; set; }

    public string? CategoryId { get; set; }

    public ProductCondition? Condition { get; set; }

    public List<string>? ImageUrls { get; set; }

    [Range(0, int.MaxValue)]
    public int? StockQuantity { get; set; }

    /// <summary>Set to false to deactivate or put out of stock (hide from listing).</summary>
    public bool? IsActive { get; set; }
}
