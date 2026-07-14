using System.Net;
using System.Net.Http.Json;

namespace Treda.IntegrationTests;

public class SubscriptionTests : IntegrationTestBase
{
    public SubscriptionTests(TredaApiFactory factory) : base(factory) { }

    private static async Task SetTierAsync(HttpClient client, string email, string tier, int days = 30)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/admin/subscriptions")
        {
            Content = JsonContent.Create(new { vendorEmail = email, tier, durationDays = days })
        };
        req.Headers.Add("X-Admin-Key", "test-admin-key");
        (await client.SendAsync(req)).EnsureSuccessStatusCode();
    }

    private static Task<HttpResponseMessage> CreateProduct(HttpClient client, string name)
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
    public async Task Free_vendor_capped_at_three_products_then_paid_can_add_more()
    {
        var client = NewClient();
        var vendor = await CreateVendorAsync(client);

        for (var i = 0; i < 3; i++)
            Assert.Equal(HttpStatusCode.Created, (await CreateProduct(client, $"P{i}")).StatusCode);

        // 4th is blocked on the free plan.
        Assert.Equal(HttpStatusCode.BadRequest, (await CreateProduct(client, "P4")).StatusCode);

        // Upgrade → can add more.
        await SetTierAsync(client, vendor.Email, "Gold");
        Assert.Equal(HttpStatusCode.Created, (await CreateProduct(client, "P5")).StatusCode);
    }

    [Fact]
    public async Task Subscription_status_reflects_tier_and_usage()
    {
        var client = NewClient();
        var vendor = await CreateVendorAsync(client);
        await CreateProduct(client, "One");

        var free = await DataAsync(await client.GetAsync("/api/vendor/subscription"));
        Assert.Equal("Free", free.GetProperty("effectiveTier").GetString());
        Assert.False(free.GetProperty("isPaid").GetBoolean());
        Assert.Equal(1, free.GetProperty("productsUsed").GetInt32());
        Assert.Equal(3, free.GetProperty("maxProducts").GetInt32());

        await SetTierAsync(client, vendor.Email, "Premium");
        var paid = await DataAsync(await client.GetAsync("/api/vendor/subscription"));
        Assert.Equal("Premium", paid.GetProperty("effectiveTier").GetString());
        Assert.True(paid.GetProperty("isPaid").GetBoolean());
        Assert.True(paid.GetProperty("canPromote").GetBoolean());
    }

    [Fact]
    public async Task Free_cannot_promote_but_paid_can_and_it_shows_in_featured()
    {
        var client = NewClient();
        var vendor = await CreateVendorAsync(client);
        var created = await DataAsync(await CreateProduct(client, "Promote me"));
        var productId = created.GetProperty("id").GetString();

        var asFree = await client.PutAsJsonAsync($"/api/products/{productId}/promote", new { promoted = true });
        Assert.Equal(HttpStatusCode.BadRequest, asFree.StatusCode);

        await SetTierAsync(client, vendor.Email, "Silver");
        var asPaid = await client.PutAsJsonAsync($"/api/products/{productId}/promote", new { promoted = true });
        Assert.Equal(HttpStatusCode.OK, asPaid.StatusCode);

        var featured = await DataAsync(await NewClient().GetAsync("/api/public/featured-products?limit=50"));
        Assert.Contains(featured.EnumerateArray(), p => p.GetProperty("id").GetString() == productId);
    }

    [Fact]
    public async Task Top_stores_lists_paid_but_not_free_stores()
    {
        var paidClient = NewClient();
        var paidVendor = await CreateVendorAsync(paidClient);
        await SetTierAsync(paidClient, paidVendor.Email, "Gold");

        var freeVendor = await CreateVendorAsync(NewClient());

        var top = await DataAsync(await NewClient().GetAsync("/api/public/top-stores?limit=50"));
        var ids = top.EnumerateArray().Select(s => s.GetProperty("id").GetString()).ToList();
        Assert.Contains(paidVendor.Id, ids);
        Assert.DoesNotContain(freeVendor.Id, ids);
    }

    [Fact]
    public async Task Free_vendor_sees_only_three_pending_orders_rest_locked()
    {
        var seller = NewClient();
        var vendor = await CreateVendorAsync(seller);
        var created = await DataAsync(await CreateProduct(seller, "Item"));
        var productId = created.GetProperty("id").GetString();

        var orderIds = new List<string>();
        for (var i = 0; i < 4; i++)
        {
            var placed = await DataAsync(await NewClient().PostAsJsonAsync("/api/public/orders", new
            {
                vendorId = vendor.Id,
                items = new[] { new { productId, quantity = 1 } },
                guestName = $"Buyer{i}",
                guestPhone = "08000000000",
                deliveryAddress = "a",
                deliveryCity = "b",
                deliveryState = "Lagos"
            }));
            orderIds.Add(placed.GetProperty("id").GetString()!);
        }

        // Free plan: list shows 3 pending + lockedCount 1.
        var list = await DataAsync(await seller.GetAsync("/api/orders?page=1&pageSize=20&status=Pending"));
        Assert.Equal(3, list.GetProperty("items").GetArrayLength());
        Assert.Equal(1, list.GetProperty("lockedCount").GetInt32());

        // The oldest pending order is locked → 403.
        Assert.Equal(HttpStatusCode.Forbidden, (await seller.GetAsync($"/api/orders/{orderIds[0]}")).StatusCode);

        // Upgrade → all 4 visible, none locked.
        await SetTierAsync(seller, vendor.Email, "Gold");
        var paidList = await DataAsync(await seller.GetAsync("/api/orders?page=1&pageSize=20&status=Pending"));
        Assert.Equal(4, paidList.GetProperty("items").GetArrayLength());
        Assert.Equal(HttpStatusCode.OK, (await seller.GetAsync($"/api/orders/{orderIds[0]}")).StatusCode);
    }

    [Fact]
    public async Task Downgrade_hides_extra_products_from_the_storefront()
    {
        var seller = NewClient();
        var vendor = await CreateVendorAsync(seller);

        await SetTierAsync(seller, vendor.Email, "Gold");   // paid → can add >3
        for (var i = 0; i < 5; i++)
            Assert.Equal(HttpStatusCode.Created, (await CreateProduct(seller, $"Prod{i}")).StatusCode);

        var paidStore = await DataAsync(await NewClient().GetAsync($"/api/public/vendors/by-slug/{vendor.Slug}"));
        Assert.Equal(5, paidStore.GetProperty("products").GetProperty("totalCount").GetInt32());

        await SetTierAsync(seller, vendor.Email, "Free");   // downgrade

        var freeStore = await DataAsync(await NewClient().GetAsync($"/api/public/vendors/by-slug/{vendor.Slug}"));
        Assert.Equal(3, freeStore.GetProperty("products").GetProperty("totalCount").GetInt32());
    }

    [Fact]
    public async Task Downgrade_hides_extra_products_from_the_catalog()
    {
        var seller = NewClient();
        var vendor = await CreateVendorAsync(seller);
        await SetTierAsync(seller, vendor.Email, "Gold");

        var oldest = $"OldItem{Guid.NewGuid():N}";
        await CreateProduct(seller, oldest);                       // oldest → hidden after downgrade
        for (var i = 0; i < 3; i++)
            await CreateProduct(seller, $"Newer{i}{Guid.NewGuid():N}");

        var paidHits = await DataAsync(await NewClient().GetAsync($"/api/public/products?search={oldest}"));
        Assert.Contains(paidHits.EnumerateArray(), p => p.GetProperty("name").GetString() == oldest);

        await SetTierAsync(seller, vendor.Email, "Free");           // downgrade → only 3 most-recent visible

        var freeHits = await DataAsync(await NewClient().GetAsync($"/api/public/products?search={oldest}"));
        Assert.DoesNotContain(freeHits.EnumerateArray(), p => p.GetProperty("name").GetString() == oldest);
    }

    [Fact]
    public async Task Admin_endpoint_requires_the_key()
    {
        var client = NewClient();
        var vendor = await CreateVendorAsync(client);

        // No X-Admin-Key header → rejected.
        var resp = await client.PostAsJsonAsync("/api/admin/subscriptions",
            new { vendorEmail = vendor.Email, tier = "Gold", durationDays = 30 });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }
}
