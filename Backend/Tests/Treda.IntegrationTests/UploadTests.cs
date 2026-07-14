using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;

namespace Treda.IntegrationTests;

/// <summary>
/// Pins the contract the frontend must follow for logo / cover-photo uploads:
/// POST /api/upload  (multipart/form-data, file field named "file", Bearer token)
/// then save the returned url via PUT /api/vendor/store-appearance.
/// </summary>
public class UploadTests : IntegrationTestBase
{
    public UploadTests(TredaApiFactory factory) : base(factory) { }

    private static MultipartFormDataContent ImageForm(string fieldName = "file", string fileName = "logo.jpg")
    {
        // Minimal JPEG magic bytes — enough for the endpoint's extension/size checks.
        var file = new ByteArrayContent(new byte[] { 0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x01 });
        file.Headers.ContentType = new MediaTypeHeaderValue("image/jpeg");

        var form = new MultipartFormDataContent();
        form.Add(file, fieldName, fileName);
        return form;
    }

    [Fact]
    public async Task Upload_without_token_is_unauthorized()
    {
        var client = NewClient(); // no Authorization header
        using var form = ImageForm();

        var response = await client.PostAsync("/api/upload", form);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Upload_with_token_returns_a_url()
    {
        var client = NewClient();
        await CreateVendorAsync(client); // sets the Bearer token on the client

        using var form = ImageForm();
        var data = await DataAsync(await client.PostAsync("/api/upload", form));

        var url = data.GetProperty("url").GetString();
        Assert.False(string.IsNullOrWhiteSpace(url));
    }

    [Fact]
    public async Task Upload_rejects_a_disallowed_file_type()
    {
        var client = NewClient();
        await CreateVendorAsync(client);

        using var form = ImageForm(fileName: "notes.txt");
        var response = await client.PostAsync("/api/upload", form);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>Send the image files straight to store-appearance — the only supported way.</summary>
    [Fact]
    public async Task Logo_and_cover_files_can_be_sent_directly_to_store_appearance()
    {
        var client = NewClient();
        await CreateVendorAsync(client);

        var logo = new ByteArrayContent(new byte[] { 0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x01 });
        logo.Headers.ContentType = new MediaTypeHeaderValue("image/jpeg");
        var cover = new ByteArrayContent(new byte[] { 0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x02 });
        cover.Headers.ContentType = new MediaTypeHeaderValue("image/jpeg");

        using var form = new MultipartFormDataContent();
        form.Add(logo, "logo", "logo.jpg");
        form.Add(cover, "cover", "cover.jpg");

        var saved = await DataAsync(await client.PutAsync("/api/vendor/store-appearance", form));

        // The files were uploaded server-side and their urls saved on the vendor.
        Assert.False(string.IsNullOrWhiteSpace(saved.GetProperty("businessLogoUrl").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(saved.GetProperty("businessCoverPhotoUrl").GetString()));
    }

    [Fact]
    public async Task Cover_changes_anytime_but_logo_has_a_cooldown()
    {
        var client = NewClient();
        await CreateVendorAsync(client);

        // Cover photo: two changes back-to-back are both allowed (no cooldown).
        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync("/api/vendor/store-appearance", ImageForm("cover"))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync("/api/vendor/store-appearance", ImageForm("cover"))).StatusCode);

        // Logo: first set is allowed, an immediate second change is rejected by the 6-month cooldown.
        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync("/api/vendor/store-appearance", ImageForm("logo"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PutAsync("/api/vendor/store-appearance", ImageForm("logo"))).StatusCode);
    }

    [Fact]
    public async Task Store_appearance_rejects_a_disallowed_logo_file_type()
    {
        var client = NewClient();
        await CreateVendorAsync(client);

        var bad = new ByteArrayContent(new byte[] { 0x01, 0x02 });
        bad.Headers.ContentType = new MediaTypeHeaderValue("text/plain");

        using var form = new MultipartFormDataContent();
        form.Add(bad, "logo", "notes.txt");

        var response = await client.PutAsync("/api/vendor/store-appearance", form);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
