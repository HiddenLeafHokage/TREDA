using System.Net.Http.Json;
using System.Text.Json;

namespace Treda.IntegrationTests;

public class NotificationTests : IntegrationTestBase
{
    public NotificationTests(TredaApiFactory factory) : base(factory) { }

    private static async Task SetTierAsync(HttpClient client, string email, string tier, int days = 30)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/admin/subscriptions")
        {
            Content = JsonContent.Create(new { vendorEmail = email, tier, durationDays = days })
        };
        req.Headers.Add("X-Admin-Key", "test-admin-key");
        (await client.SendAsync(req)).EnsureSuccessStatusCode();
    }

    private async Task<List<JsonElement>> NotificationsAsync(HttpClient seller)
    {
        var page = await DataAsync(await seller.GetAsync("/api/vendor/notifications?category=all&page=1&pageSize=50"));
        return page.GetProperty("items").EnumerateArray().ToList();
    }

    [Fact]
    public async Task Order_lifecycle_and_plan_changes_create_notifications()
    {
        var seller = NewClient();
        var vendor = await CreateVendorAsync(seller);

        var product = await DataAsync(await seller.PostAsJsonAsync("/api/products", new
        {
            name = "Notify Item",
            description = "x",
            price = 1000,
            categoryId = "cat-food",
            condition = "New",
            imageUrls = Array.Empty<string>(),
            stockQuantity = 10,
            isActive = true
        }));
        var productId = product.GetProperty("id").GetString();

        // Buyer places an order → "new order" notification.
        var placed = await DataAsync(await NewClient().PostAsJsonAsync("/api/public/orders", new
        {
            vendorId = vendor.Id,
            items = new[] { new { productId, quantity = 1 } },
            guestName = "Buyer",
            guestPhone = "08000000000",
            deliveryAddress = "a",
            deliveryCity = "b",
            deliveryState = "Lagos"
        }));
        var orderId = placed.GetProperty("id").GetString();

        // Status change → notification.
        await seller.PutAsJsonAsync($"/api/orders/{orderId}/status", new { status = "Shipped" });
        // Payment marked Paid → notification.
        await seller.PutAsJsonAsync($"/api/orders/{orderId}/payment-status", new { paymentStatus = "Paid" });
        // Plan granted → notification (and unlocks promote).
        await SetTierAsync(seller, vendor.Email, "Gold");
        // Promote → notification.
        await seller.PutAsJsonAsync($"/api/products/{productId}/promote", new { promoted = true });

        var notifications = await NotificationsAsync(seller);
        var titles = notifications.Select(n => n.GetProperty("title").GetString() ?? "").ToList();

        Assert.Contains(titles, t => t.Contains("New order", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(titles, t => t.Contains("Shipped", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(titles, t => t.Contains("Gold plan", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(titles, t => t.Contains("Listing promoted", StringComparison.OrdinalIgnoreCase));
    }
}
