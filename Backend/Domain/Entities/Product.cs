using System.ComponentModel.DataAnnotations;

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
    
    public string Category { get; set; } = string.Empty;
    public List<string> ImageUrls { get; set; } = new();
    public int StockQuantity { get; set; }
    public bool IsActive { get; set; } = true;
    
    // Foreign key
    public string SellerId { get; set; } = string.Empty;
    public User? Seller { get; set; }
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
