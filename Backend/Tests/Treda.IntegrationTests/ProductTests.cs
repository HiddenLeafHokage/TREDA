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

    [Fact]
    public async Task Discount_price_must_be_lower_than_price()
    {
        var client = NewClient();
        await CreateVendorAsync(client, categoryId: "cat-food");

        var create = await client.PostAsJsonAsync("/api/products", new
        {
            name = "Overpriced discount",
            description = "x",
            price = 1000,
            discountPrice = 1000, // not lower than price → rejected
            categoryId = "cat-food",
            condition = "New",
            imageUrls = Array.Empty<string>(),
            stockQuantity = 5,
            isActive = true
        });

        Assert.Equal(HttpStatusCode.BadRequest, create.StatusCode);

        var ok = await DataAsync(await client.PostAsJsonAsync("/api/products", new
        {
            name = "Valid discount",
            description = "x",
            price = 1000,
            discountPrice = 800,
            categoryId = "cat-food",
            condition = "New",
            imageUrls = Array.Empty<string>(),
            stockQuantity = 5,
            isActive = true
        }));
        Assert.Equal(800m, ok.GetProperty("discountPrice").GetDecimal());
    }

    [Fact]
    public async Task Draft_product_is_hidden_until_published_and_does_not_count_toward_the_free_cap()
    {
        var client = NewClient();
        await CreateVendorAsync(client, categoryId: "cat-food");

        var draft = await DataAsync(await client.PostAsJsonAsync("/api/products", new
        {
            name = "Draft Item",
            description = "x",
            price = 500,
            categoryId = "cat-food",
            condition = "New",
            imageUrls = Array.Empty<string>(),
            stockQuantity = 5,
            isActive = true,
            status = "Draft"
        }));
        var draftId = draft.GetProperty("id").GetString();
        Assert.Equal("Draft", draft.GetProperty("status").GetString());

        // Not visible publicly while a draft.
        var publicList = await DataAsync(await NewClient().GetAsync("/api/public/products?page=1&pageSize=20"));
        Assert.DoesNotContain(publicList.EnumerateArray(), p => p.GetProperty("id").GetString() == draftId);

        // A draft doesn't use up the free plan's 3-product cap.
        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(HttpStatusCode.Created, (await client.PostAsJsonAsync("/api/products", new
            {
                name = $"Published{i}",
                description = "x",
                price = 500,
                categoryId = "cat-food",
                condition = "New",
                imageUrls = Array.Empty<string>(),
                stockQuantity = 5,
                isActive = true
            })).StatusCode);
        }

        // Publishing the draft now hits the cap (3 published already exist).
        var publishBlocked = await client.PutAsync($"/api/products/{draftId}/publish", null);
        Assert.Equal(HttpStatusCode.BadRequest, publishBlocked.StatusCode);
    }
}
