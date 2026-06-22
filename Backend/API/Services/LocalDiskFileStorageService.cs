using Application.Interfaces;

namespace API.Services;

/// <summary>
/// Development/fallback storage that writes to wwwroot/uploads on local disk.
///
/// WARNING: On hosts with an ephemeral filesystem (e.g. Render's default service disk),
/// these files are wiped on every redeploy/restart. Use <see cref="Application.Services.CloudinaryFileStorageService"/>
/// in production. Program.cs selects this implementation only when Cloudinary is NOT configured.
/// </summary>
public class LocalDiskFileStorageService : IFileStorageService
{
    private readonly IWebHostEnvironment _env;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IConfiguration _configuration;

    public LocalDiskFileStorageService(
        IWebHostEnvironment env,
        IHttpContextAccessor httpContextAccessor,
        IConfiguration configuration)
    {
        _env = env;
        _httpContextAccessor = httpContextAccessor;
        _configuration = configuration;
    }

    public async Task<StoredFile> UploadAsync(Stream content, string fileName, string contentType, CancellationToken cancellationToken = default)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        var safeName = $"{Guid.NewGuid():N}{ext}";

        var uploadsDir = Path.Combine(_env.ContentRootPath, "wwwroot", "uploads");
        Directory.CreateDirectory(uploadsDir);
        var filePath = Path.Combine(uploadsDir, safeName);

        await using (var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, useAsync: true))
            await content.CopyToAsync(stream, cancellationToken);

        var relativeUrl = $"/uploads/{safeName}";
        return new StoredFile(BuildPublicUrl(relativeUrl), relativeUrl);
    }

    public Task DeleteAsync(string? publicId, CancellationToken cancellationToken = default)
    {
        // publicId here is the relative URL, e.g. "/uploads/abc.jpg".
        DeleteByFileName(publicId);
        return Task.CompletedTask;
    }

    public Task DeleteByUrlAsync(string? url, CancellationToken cancellationToken = default)
    {
        // Works for both absolute ("https://host/uploads/abc.jpg") and relative ("/uploads/abc.jpg") URLs.
        DeleteByFileName(url);
        return Task.CompletedTask;
    }

    private void DeleteByFileName(string? pathOrUrl)
    {
        if (string.IsNullOrWhiteSpace(pathOrUrl))
            return;

        var fileName = Path.GetFileName(new Uri(pathOrUrl, UriKind.RelativeOrAbsolute).IsAbsoluteUri
            ? new Uri(pathOrUrl).AbsolutePath
            : pathOrUrl);

        if (string.IsNullOrWhiteSpace(fileName))
            return;

        var filePath = Path.Combine(_env.ContentRootPath, "wwwroot", "uploads", fileName);
        if (File.Exists(filePath))
            File.Delete(filePath);
    }

    private string BuildPublicUrl(string relativeUrl)
    {
        var configuredBaseUrl = _configuration["Uploads:PublicBaseUrl"]?.Trim().TrimEnd('/');
        if (!string.IsNullOrWhiteSpace(configuredBaseUrl))
            return $"{configuredBaseUrl}{relativeUrl}";

        // Request scheme/host is already corrected by UseForwardedHeaders() for proxied hosts.
        var request = _httpContextAccessor.HttpContext?.Request;
        if (request != null)
            return $"{request.Scheme}://{request.Host}{relativeUrl}";

        return relativeUrl;
    }
}
