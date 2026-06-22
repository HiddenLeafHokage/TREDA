using System.Net;
using System.Net.Http.Json;

namespace Treda.IntegrationTests;

public class ProductTests : IntegrationTestBase
{
    public ProductTests(TredaApiFactory factory) : base(factory) { }

    [Fact]
    public async Task Create_product_in_selected_category_succeeds()
    {
        var client = NewClient();
        await CreateVendorAsync(client, categoryId: "cat-food");

        var create = await client.PostAsJsonAsync("/api/products", new
        {
            name = "Rice Bag 50kg",
            description = "Premium parboiled rice.",
            price = 65000,
            categoryId = "cat-food",
            condition = "New",
            imageUrls = new[] { "/uploads/sample.jpg" },
            stockQuantity = 10,
            isActive = true
        });

        var data = await DataAsync(create);
        Assert.Equal("Rice Bag 50kg", data.GetProperty("name").GetString());
        Assert.Equal("cat-food", data.GetProperty("categoryId").GetString());
        var productId = data.GetProperty("id").GetString();

        // It comes back when listed.
        var list = await DataAsync(await client.GetAsync("/api/products?page=1&pageSize=20"));
        var items = list.GetProperty("items");
        Assert.Contains(items.EnumerateArray(), p => p.GetProperty("id").GetString() == productId);
    }

    [Fact]
    public async Task Create_product_in_unselected_category_is_rejected()
    {
        var client = NewClient();
        // Vendor only selected cat-food, so cat-electronics must be refused.
        await CreateVendorAsync(client, categoryId: "cat-food");

        var create = await client.PostAsJsonAsync("/api/products", new
        {
            name = "Phone",
            description = "Should be rejected.",
            price = 100000,
            categoryId = "cat-electronics",
            condition = "New",
            imageUrls = Array.Empty<string>(),
            stockQuantity = 5,
            isActive = true
        });

        Assert.Equal(HttpStatusCode.BadRequest, create.StatusCode);
    }
}
