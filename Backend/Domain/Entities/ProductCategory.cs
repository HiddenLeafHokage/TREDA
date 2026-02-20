using System.ComponentModel.DataAnnotations;

namespace Domain.Entities;

/// <summary>Jiji-style categories: Phones, Electronics, Fashion, Food & Beverage, Accessories, etc.</summary>
public class ProductCategory
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(100)]
    public string Slug { get; set; } = string.Empty;

    [MaxLength(500)]
    public string? Description { get; set; }

    public bool IsActive { get; set; } = true;
    public int DisplayOrder { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
