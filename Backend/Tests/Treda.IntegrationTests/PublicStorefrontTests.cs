using System.Net;
using System.Net.Http.Json;

namespace Treda.IntegrationTests;

public class PublicStorefrontTests : IntegrationTestBase
{
    public PublicStorefrontTests(TredaApiFactory factory) : base(factory) { }

    [Fact]
    public async Task Storefront_by_slug_returns_vendor_and_active_products()
    {
        var client = NewClient();
        var vendor = await CreateVendorAsync(client, categoryId: "cat-food");

        await client.PostAsJsonAsync("/api/products", new
        {
            name = "Beans Bag",
            description = "Honey beans.",
            price = 40000,
            categoryId = "cat-food",
            condition = "New",
            imageUrls = new[] { "/uploads/beans.jpg" },
            stockQuantity = 7,
            isActive = true
        });

        // Public call — no auth header.
        var publicClient = NewClient();
        var data = await DataAsync(await publicClient.GetAsync($"/api/public/vendors/by-slug/{vendor.Slug}"));

        Assert.Equal(vendor.Slug, data.GetProperty("slug").GetString());
        var products = data.GetProperty("products").GetProperty("items");
        Assert.Contains(products.EnumerateArray(), p => p.GetProperty("name").GetString() == "Beans Bag");
    }

    [Fact]
    public async Task Storefront_by_unknown_slug_returns_404()
    {
        var publicClient = NewClient();
        var response = await publicClient.GetAsync("/api/public/vendors/by-slug/this-shop-does-not-exist");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
