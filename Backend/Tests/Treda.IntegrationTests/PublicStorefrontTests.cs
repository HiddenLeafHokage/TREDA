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

    private static Task<HttpResponseMessage> CreateProductAsync(HttpClient client, string name)
        => client.PostAsJsonAsync("/api/products", new
        {
            name,
            description = "x",
            price = 100,
            categoryId = "cat-food",
            condition = "New",
            imageUrls = Array.Empty<string>(),
            stockQuantity = 5,
            isActive = true
        });

    [Fact]
    public async Task Shop_directory_hides_stores_with_no_products()
    {
        var withProduct = NewClient();
        var v1 = await CreateVendorAsync(withProduct, categoryId: "cat-food");
        await CreateProductAsync(withProduct, "Has a product");

        var noProducts = NewClient();
        var v2 = await CreateVendorAsync(noProducts, categoryId: "cat-food"); // no products created

        var list = await DataAsync(await NewClient().GetAsync("/api/public/vendors?pageSize=100"));
        var ids = list.GetProperty("items").EnumerateArray().Select(v => v.GetProperty("id").GetString()).ToList();

        Assert.Contains(v1.Id, ids);
        Assert.DoesNotContain(v2.Id, ids);
    }

    [Fact]
    public async Task Top_stores_include_the_shop_description()
    {
        var client = NewClient();
        var vendor = await CreateVendorAsync(client);
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/admin/subscriptions")
        {
            Content = JsonContent.Create(new { vendorEmail = vendor.Email, tier = "Gold", durationDays = 30 })
        };
        req.Headers.Add("X-Admin-Key", "test-admin-key");
        (await client.SendAsync(req)).EnsureSuccessStatusCode();

        var top = await DataAsync(await NewClient().GetAsync("/api/public/top-stores?limit=50"));
        var store = top.EnumerateArray().First(s => s.GetProperty("id").GetString() == vendor.Id);
        Assert.Equal("A shop created by the integration tests.", store.GetProperty("shopDescription").GetString());
    }
}
