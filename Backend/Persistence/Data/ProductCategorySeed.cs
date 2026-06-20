namespace Persistence.Data;

/// <summary>Product category IDs aligned with frontend CATEGORY_OPTIONS.</summary>
public static class ProductCategorySeed
{
    public sealed record CategoryDef(string Id, string Name, string Slug, int DisplayOrder);

    private static readonly DateTime SeedCreatedAt = new(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public static readonly CategoryDef[] All =
    {
        new("cat-fashion", "Fashion & Clothing", "fashion-clothing", 1),
        new("cat-electronics", "Electronics & Gadgets", "electronics-gadgets", 2),
        new("cat-home", "Home & Kitchen", "home-kitchen", 3),
        new("cat-care", "Beauty & Skincare", "beauty-skincare", 4),
        new("cat-health", "Health & Wellness", "health-wellness", 5),
        new("cat-sport", "Sports & Fitness", "sports-fitness", 6),
        new("cat-food", "Food & Groceries", "food-groceries", 7),
        new("cat-book", "Books & Stationery", "books-stationery", 8),
        new("cat-game", "Toys & Games", "toys-games", 9),
        new("cat-kid", "Baby & Kids", "baby-kids", 10),
        new("cat-vehicle", "Automobiles & Parts", "automobiles-parts", 11),
        new("cat-decor", "Furniture & Decor", "furniture-decor", 12),
        new("cat-jewelry", "Jewelry & Accessories", "jewelry-accessories", 13),
        new("cat-farm", "Agriculture & Farm Supplies", "agriculture-farm", 14),
        new("cat-art", "Art & Crafts", "art-crafts", 15),
        new("cat-build", "Building & Construction", "building-construction", 16),
        new("cat-service", "Services", "services", 17),
        new("cat-other", "Other", "other", 99),
    };

    public static readonly IReadOnlyDictionary<string, string> LegacyIdMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["cat-phones"] = "cat-electronics",
        ["cat-accessories"] = "cat-jewelry",
        ["cat-vehicles"] = "cat-vehicle",
    };

    public static Domain.Entities.ProductCategory[] ToHasDataEntities() =>
        All.Select(c => new Domain.Entities.ProductCategory
        {
            Id = c.Id,
            Name = c.Name,
            Slug = c.Slug,
            Description = c.Name,
            IsActive = true,
            DisplayOrder = c.DisplayOrder,
            CreatedAt = SeedCreatedAt
        }).ToArray();
}
