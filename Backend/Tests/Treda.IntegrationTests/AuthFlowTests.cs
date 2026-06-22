using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Treda.IntegrationTests;

public class AuthFlowTests : IntegrationTestBase
{
    public AuthFlowTests(TredaApiFactory factory) : base(factory) { }

    [Fact]
    public async Task Register_Verify_Login_succeeds_and_returns_token()
    {
        var client = NewClient();
        var vendor = await CreateVendorAsync(client);

        Assert.False(string.IsNullOrWhiteSpace(vendor.Token));
        Assert.False(string.IsNullOrWhiteSpace(vendor.Slug));

        // The token works against a protected endpoint.
        var profile = await client.GetAsync("/api/vendor/profile");
        Assert.Equal(HttpStatusCode.OK, profile.StatusCode);
    }

    [Fact]
    public async Task Register_with_optional_logo_saves_it()
    {
        var client = NewClient();
        await CreateVendorAsync(client, logoUrl: "/uploads/my-logo.jpg");

        var profile = await DataAsync(await client.GetAsync("/api/vendor/profile"));
        Assert.Equal("/uploads/my-logo.jpg", profile.GetProperty("businessLogoUrl").GetString());
    }

    [Fact]
    public async Task Register_without_logo_falls_back_to_initial()
    {
        var client = NewClient();
        await CreateVendorAsync(client); // no logo provided

        var profile = await DataAsync(await client.GetAsync("/api/vendor/profile"));
        Assert.Equal(JsonValueKind.Null, profile.GetProperty("businessLogoUrl").ValueKind);

        var initial = profile.GetProperty("branding").GetProperty("displayInitial").GetString();
        Assert.False(string.IsNullOrEmpty(initial));
    }

    [Fact]
    public async Task Login_before_verification_is_forbidden()
    {
        var client = NewClient();
        var email = $"unverified-{Guid.NewGuid():N}@example.com";
        var phone = $"080{Random.Shared.Next(10_000_000, 99_999_999)}";

        var register = await client.PostAsJsonAsync("/api/auth/register-vendor", new
        {
            fullName = "Unverified Owner",
            businessName = $"Unverified {Guid.NewGuid():N}"[..18],
            email,
            phoneNumber = phone,
            password = "Password@123",
            confirmPassword = "Password@123",
            businessCategoryIds = new[] { "cat-food" },
            businessLocation = "Lagos",
            shopDescription = "Not verified yet.",
            deliveryMethod = "Both",
            caC_RC_Number = "BN-1234"
        });
        register.EnsureSuccessStatusCode();

        var login = await client.PostAsJsonAsync("/api/auth/login", new { email, password = "Password@123", rememberMe = false });
        Assert.Equal(HttpStatusCode.Forbidden, login.StatusCode);
    }

    [Fact]
    public async Task Verify_with_wrong_code_is_rejected()
    {
        var client = NewClient();
        var email = $"wrongcode-{Guid.NewGuid():N}@example.com";
        var phone = $"080{Random.Shared.Next(10_000_000, 99_999_999)}";

        var register = await client.PostAsJsonAsync("/api/auth/register-vendor", new
        {
            fullName = "Wrong Code",
            businessName = $"WrongCode {Guid.NewGuid():N}"[..18],
            email,
            phoneNumber = phone,
            password = "Password@123",
            confirmPassword = "Password@123",
            businessCategoryIds = new[] { "cat-food" },
            businessLocation = "Kano",
            shopDescription = "Will fail verification.",
            deliveryMethod = "Both",
            caC_RC_Number = "BN-9999"
        });
        register.EnsureSuccessStatusCode();

        var verify = await client.PostAsJsonAsync("/api/auth/verify-email", new { email, verificationCode = "000000" });
        Assert.Equal(HttpStatusCode.BadRequest, verify.StatusCode);
    }
}
