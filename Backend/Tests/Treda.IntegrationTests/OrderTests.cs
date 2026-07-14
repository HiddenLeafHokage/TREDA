using System.Net;
using System.Net.Http.Json;

namespace Treda.IntegrationTests;

public class OrderTests : IntegrationTestBase
{
    public OrderTests(TredaApiFactory factory) : base(factory) { }

    private async Task<string> CreateProductAsync(HttpClient sellerClient, string name, decimal price)
    {
        var created = await DataAsync(await sellerClient.PostAsJsonAsync("/api/products", new
        {
            name,
            description = "test",
            price,
            categoryId = "cat-food",
            condition = "New",
            imageUrls = Array.Empty<string>(),
            stockQuantity = 100,
            isActive = true
        }));
        return created.GetProperty("id").GetString()!;
    }

    [Fact]
    public async Task Guest_places_multi_item_order_and_vendor_sees_it()
    {
        var seller = NewClient();
        var vendor = await CreateVendorAsync(seller, categoryId: "cat-food");
        var rice = await CreateProductAsync(seller, "Rice", 1000);
        var beans = await CreateProductAsync(seller, "Beans", 500);

        // Guest checkout — no auth.
        var buyer = NewClient();
        var placed = await DataAsync(await buyer.PostAsJsonAsync("/api/public/orders", new
        {
            vendorId = vendor.Id,
            items = new[] { new { productId = rice, quantity = 2 }, new { productId = beans, quantity = 3 } },
            guestName = "John Buyer",
            guestPhone = "08011112222",
            deliveryAddress = "15 Adebanjo Street",
            deliveryCity = "Ikeja",
            deliveryState = "Lagos",
            deliveryNote = "call before arriving"
        }));

        Assert.Equal(3500m, placed.GetProperty("subtotal").GetDecimal()); // 2*1000 + 3*500
        Assert.Equal(3500m, placed.GetProperty("total").GetDecimal());    // no delivery fee yet
        Assert.Equal("Pending", placed.GetProperty("status").GetString());
        Assert.Equal("AwaitingPayment", placed.GetProperty("paymentStatus").GetString());
        Assert.Equal(2, placed.GetProperty("items").GetArrayLength());
        var orderId = placed.GetProperty("id").GetString()!;

        // Vendor sees it in the orders list.
        var list = await DataAsync(await seller.GetAsync("/api/orders?page=1&pageSize=20"));
        Assert.Contains(list.GetProperty("items").EnumerateArray(), o => o.GetProperty("id").GetString() == orderId);

        // Vendor detail shows the delivery + contact + snapshotted method.
        var detail = await DataAsync(await seller.GetAsync($"/api/orders/{orderId}"));
        Assert.Equal("Lagos", detail.GetProperty("deliveryState").GetString());
        Assert.Equal("08011112222", detail.GetProperty("guestPhone").GetString());
        Assert.Equal("Both", detail.GetProperty("deliveryMethod").GetString()); // vendor registered with Both
    }

    [Fact]
    public async Task Vendor_sets_delivery_fee_changes_status_and_marks_paid()
    {
        var seller = NewClient();
        var vendor = await CreateVendorAsync(seller);
        var yam = await CreateProductAsync(seller, "Yam", 2000);

        var buyer = NewClient();
        var placed = await DataAsync(await buyer.PostAsJsonAsync("/api/public/orders", new
        {
            vendorId = vendor.Id,
            items = new[] { new { productId = yam, quantity = 1 } },
            guestName = "Jane",
            guestPhone = "08000000000",
            deliveryAddress = "x",
            deliveryCity = "y",
            deliveryState = "Lagos"
        }));
        var orderId = placed.GetProperty("id").GetString()!;

        // Set delivery fee → total becomes 2000 + 500.
        var withFee = await DataAsync(await seller.PutAsJsonAsync($"/api/orders/{orderId}", new { deliveryFee = 500 }));
        Assert.Equal(500m, withFee.GetProperty("deliveryFee").GetDecimal());
        Assert.Equal(2500m, withFee.GetProperty("total").GetDecimal());

        // Change fulfilment status.
        var shipped = await DataAsync(await seller.PutAsJsonAsync($"/api/orders/{orderId}/status", new { status = "Shipped" }));
        Assert.Equal("Shipped", shipped.GetProperty("status").GetString());

        // Mark paid (payment status is independent of order status).
        var paid = await DataAsync(await seller.PutAsJsonAsync($"/api/orders/{orderId}/payment-status", new { paymentStatus = "Paid" }));
        Assert.Equal("Paid", paid.GetProperty("paymentStatus").GetString());
        Assert.Equal("Shipped", paid.GetProperty("status").GetString());
    }

    [Fact]
    public async Task Invoice_returns_from_to_and_totals()
    {
        var seller = NewClient();
        var vendor = await CreateVendorAsync(seller);
        var p = await CreateProductAsync(seller, "Garri", 1200);

        var buyer = NewClient();
        var placed = await DataAsync(await buyer.PostAsJsonAsync("/api/public/orders", new
        {
            vendorId = vendor.Id,
            items = new[] { new { productId = p, quantity = 2 } },
            guestName = "Ada Buyer",
            guestPhone = "08099998888",
            deliveryAddress = "12 Market Rd",
            deliveryCity = "Aba",
            deliveryState = "Abia"
        }));
        var orderId = placed.GetProperty("id").GetString()!;
        await seller.PutAsJsonAsync($"/api/orders/{orderId}", new { deliveryFee = 800 });

        var invoice = await DataAsync(await seller.GetAsync($"/api/orders/{orderId}/invoice"));

        Assert.StartsWith("INV-", invoice.GetProperty("invoiceNumber").GetString());
        Assert.Equal("Ada Buyer", invoice.GetProperty("toName").GetString());
        Assert.Equal("08099998888", invoice.GetProperty("toPhone").GetString());
        Assert.False(string.IsNullOrEmpty(invoice.GetProperty("fromStoreName").GetString()));
        Assert.Equal(2400m, invoice.GetProperty("subtotal").GetDecimal()); // 2 * 1200
        Assert.Equal(800m, invoice.GetProperty("deliveryFee").GetDecimal());
        Assert.Equal(3200m, invoice.GetProperty("total").GetDecimal());
    }

    [Fact]
    public async Task Order_with_unknown_product_is_rejected()
    {
        var seller = NewClient();
        var vendor = await CreateVendorAsync(seller);

        var buyer = NewClient();
        var response = await buyer.PostAsJsonAsync("/api/public/orders", new
        {
            vendorId = vendor.Id,
            items = new[] { new { productId = "does-not-exist", quantity = 1 } },
            guestName = "X",
            guestPhone = "08000000000",
            deliveryAddress = "a",
            deliveryCity = "b",
            deliveryState = "Lagos"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
