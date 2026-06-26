using System.Net;
using System.Net.Http.Headers;
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
    public async Task New_vendor_has_no_logo_and_shows_first_letter_initial()
    {
        var client = NewClient();
        await CreateVendorAsync(client); // registration never sets a logo

        var profile = await DataAsync(await client.GetAsync("/api/vendor/profile"));
        Assert.Equal(JsonValueKind.Null, profile.GetProperty("businessLogoUrl").ValueKind);

        var initial = profile.GetProperty("branding").GetProperty("displayInitial").GetString();
        Assert.False(string.IsNullOrEmpty(initial));
    }

    [Fact]
    public async Task Register_vendor_with_logo_saves_the_logo()
    {
        var client = NewClient();
        var email = $"logo-{Guid.NewGuid():N}@example.com";
        var phone = $"080{Random.Shared.Next(10_000_000, 99_999_999)}";

        using var form = new MultipartFormDataContent
        {
            { new StringContent("Logo Owner"), "fullName" },
            { new StringContent($"Logo Shop {Guid.NewGuid():N}"[..20]), "businessName" },
            { new StringContent(email), "email" },
            { new StringContent(phone), "phoneNumber" },
            { new StringContent("Password@123"), "password" },
            { new StringContent("Password@123"), "confirmPassword" },
            { new StringContent("cat-food"), "businessCategoryIds" },
            { new StringContent("Abuja, Nigeria"), "businessLocation" },
            { new StringContent("A shop with a logo."), "shopDescription" },
            { new StringContent("Both"), "deliveryMethod" },
            { new StringContent("BN-4321"), "caC_RC_Number" },
        };
        var image = new ByteArrayContent(new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 });
        image.Headers.ContentType = new MediaTypeHeaderValue("image/jpeg");
        form.Add(image, "logo", "logo.jpg");

        var data = await DataAsync(await client.PostAsync("/api/auth/register-vendor", form));
        var token = data.GetProperty("token").GetString();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var profile = await DataAsync(await client.GetAsync("/api/vendor/profile"));

        var logoUrl = profile.GetProperty("businessLogoUrl");
        Assert.Equal(JsonValueKind.String, logoUrl.ValueKind);
        Assert.False(string.IsNullOrEmpty(logoUrl.GetString()));
    }

    [Fact]
    public async Task Login_before_verification_is_forbidden()
    {
        var client = NewClient();
        var email = $"unverified-{Guid.NewGuid():N}@example.com";
        var phone = $"080{Random.Shared.Next(10_000_000, 99_999_999)}";

        using var form = VendorForm(email, phone);
        var register = await client.PostAsync("/api/auth/register-vendor", form);
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

        using var form = VendorForm(email, phone);
        var register = await client.PostAsync("/api/auth/register-vendor", form);
        register.EnsureSuccessStatusCode();

        var verify = await client.PostAsJsonAsync("/api/auth/verify-email", new { email, verificationCode = "000000" });
        Assert.Equal(HttpStatusCode.BadRequest, verify.StatusCode);
    }
}
