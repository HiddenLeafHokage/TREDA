using Domain.Enums;

namespace Application.DTOs.Product;

public class ProductResponseDto
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public decimal Price { get; set; }
    public string CategoryId { get; set; } = string.Empty;
    public string CategoryName { get; set; } = string.Empty;
    public string Condition { get; set; } = string.Empty; // New, Used, Refurbished
    public string? Location { get; set; }
    public List<string> ImageUrls { get; set; } = new();
    public int StockQuantity { get; set; }
    public bool IsActive { get; set; }
    public string VendorId { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
