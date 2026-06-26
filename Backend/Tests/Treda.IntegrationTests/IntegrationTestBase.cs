using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Persistence.Data;

namespace Treda.IntegrationTests;

/// <summary>Shares a single API host + Postgres container across all test classes in the "api" collection.</summary>
[CollectionDefinition("api")]
public class ApiCollection : ICollectionFixture<TredaApiFactory> { }

[Collection("api")]
public abstract class IntegrationTestBase
{
    protected readonly TredaApiFactory Factory;

    protected IntegrationTestBase(TredaApiFactory factory) => Factory = factory;

    protected HttpClient NewClient() => Factory.CreateClient();

    /// <summary>A registered, verified, logged-in vendor with the given category selected.</summary>
    protected record Vendor(string Id, string Email, string Token, string Slug);

    /// <summary>
    /// Builds the multipart registration form (no logo). Registration is multipart/form-data;
    /// add a "logo" file part to the returned content to include a logo.
    /// </summary>
    protected static MultipartFormDataContent VendorForm(string email, string phone, string categoryId = "cat-food")
        => new()
        {
            { new StringContent("Test Owner"), "fullName" },
            { new StringContent($"Test Shop {Guid.NewGuid():N}"[..20]), "businessName" },
            { new StringContent(email), "email" },
            { new StringContent(phone), "phoneNumber" },
            { new StringContent("Password@123"), "password" },
            { new StringContent("Password@123"), "confirmPassword" },
            { new StringContent(categoryId), "businessCategoryIds" },
            { new StringContent("Abuja, Nigeria"), "businessLocation" },
            { new StringContent("A shop created by the integration tests."), "shopDescription" },
            { new StringContent("Both"), "deliveryMethod" },
            { new StringContent("BN-4321"), "caC_RC_Number" },
        };

    /// <summary>Registers a vendor, reads the code from the DB, verifies, logs in, and returns the session.</summary>
    protected async Task<Vendor> CreateVendorAsync(HttpClient client, string categoryId = "cat-food")
    {
        var email = $"vendor-{Guid.NewGuid():N}@example.com";
        var phone = $"080{Random.Shared.Next(10_000_000, 99_999_999)}";

        using var form = VendorForm(email, phone, categoryId);
        var register = await client.PostAsync("/api/auth/register-vendor", form);
        var userId = (await DataAsync(register)).GetProperty("id").GetString()!;

        var code = await GetVerificationCodeAsync(userId);

        var verify = await client.PostAsJsonAsync("/api/auth/verify-email", new { email, verificationCode = code });
        verify.EnsureSuccessStatusCode();

        var login = await client.PostAsJsonAsync("/api/auth/login", new { email, password = "Password@123", rememberMe = true });
        var token = (await DataAsync(login)).GetProperty("token").GetString()!;

        client.DefaultRequestHeaders.Authorization = new("Bearer", token);

        var profile = await client.GetAsync("/api/vendor/profile");
        var slug = (await DataAsync(profile)).GetProperty("businessSlug").GetString()!;

        return new Vendor(userId, email, token, slug);
    }

    /// <summary>Reads the latest verification code straight from the database (no email needed in tests).</summary>
    protected async Task<string> GetVerificationCodeAsync(string userId)
    {
        using var scope = Factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TredaDbContext>();
        return await db.EmailVerificationTokens
            .Where(t => t.UserId == userId)
            .OrderByDescending(t => t.CreatedAt)
            .Select(t => t.Token)
            .FirstAsync();
    }

    /// <summary>Asserts success and returns the <c>data</c> element of the ApiResponse envelope.</summary>
    protected static async Task<JsonElement> DataAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"Expected success but got {(int)response.StatusCode}. Body: {body}");
        using var doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty("data").Clone();
    }
}
