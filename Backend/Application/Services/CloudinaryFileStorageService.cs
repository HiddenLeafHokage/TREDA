using Application.Interfaces;
using CloudinaryDotNet;
using CloudinaryDotNet.Actions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Application.Services;

/// <summary>
/// Cloudinary-backed file storage. Returns permanent CDN URLs that survive Render redeploys.
/// Reads config from Cloudinary:CloudName / Cloudinary:ApiKey / Cloudinary:ApiSecret
/// (env vars Cloudinary__CloudName, etc. on Render).
/// </summary>
public class CloudinaryFileStorageService : IFileStorageService
{
    private readonly Cloudinary _cloudinary;
    private readonly ILogger<CloudinaryFileStorageService> _logger;
    private readonly string _folder;

    public CloudinaryFileStorageService(IConfiguration configuration, ILogger<CloudinaryFileStorageService> logger)
    {
        _logger = logger;

        var cloudName = configuration["Cloudinary:CloudName"];
        var apiKey    = configuration["Cloudinary:ApiKey"];
        var apiSecret = configuration["Cloudinary:ApiSecret"];
        _folder       = configuration["Cloudinary:Folder"]?.Trim().Trim('/') ?? "treda";

        if (string.IsNullOrWhiteSpace(cloudName) ||
            string.IsNullOrWhiteSpace(apiKey) ||
            string.IsNullOrWhiteSpace(apiSecret))
        {
            // Should never happen: Program.cs only registers this implementation when configured.
            throw new InvalidOperationException(
                "Cloudinary is not configured. Set Cloudinary__CloudName, Cloudinary__ApiKey and Cloudinary__ApiSecret.");
        }

        _cloudinary = new Cloudinary(new Account(cloudName, apiKey, apiSecret))
        {
            Api = { Secure = true }
        };
    }

    public async Task<StoredFile> UploadAsync(Stream content, string fileName, string contentType, CancellationToken cancellationToken = default)
    {
        var isImage = !string.IsNullOrWhiteSpace(contentType) &&
                      contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase);

        if (isImage)
        {
            var imageParams = new ImageUploadParams
            {
                File = new FileDescription(fileName, content),
                Folder = _folder,
                UseFilename = false,
                UniqueFilename = true,
                Overwrite = false
            };

            var imageResult = await _cloudinary.UploadAsync(imageParams, cancellationToken);
            return ToStoredFile(imageResult, fileName);
        }

        // Non-images (e.g. CAC/RC PDFs) go to Cloudinary's "raw" resource type.
        var rawParams = new RawUploadParams
        {
            File = new FileDescription(fileName, content),
            Folder = _folder,
            UseFilename = false,
            UniqueFilename = true,
            Overwrite = false
        };

        var rawResult = await _cloudinary.UploadAsync(rawParams);
        return ToStoredFile(rawResult, fileName);
    }

    public async Task DeleteAsync(string? publicId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(publicId))
            return;

        try
        {
            await _cloudinary.DestroyAsync(new DeletionParams(publicId));
        }
        catch (Exception ex)
        {
            // Deletion is best-effort — a leftover asset must never break the request flow.
            _logger.LogWarning(ex, "Failed to delete Cloudinary asset {PublicId}", publicId);
        }
    }

    public async Task DeleteByUrlAsync(string? url, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(url) ||
            !url.Contains("res.cloudinary.com", StringComparison.OrdinalIgnoreCase))
        {
            // Empty, or a URL from a different provider (e.g. legacy local-disk URL) — nothing to do here.
            return;
        }

        var (publicId, resourceType) = ParsePublicId(url);
        if (string.IsNullOrWhiteSpace(publicId))
            return;

        try
        {
            await _cloudinary.DestroyAsync(new DeletionParams(publicId) { ResourceType = resourceType });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to delete Cloudinary asset from URL {Url}", url);
        }
    }

    /// <summary>
    /// Extracts the Cloudinary public_id and resource type from a delivery URL such as
    /// https://res.cloudinary.com/&lt;cloud&gt;/image/upload/v123/treda/abc123.jpg → ("treda/abc123", Image).
    /// Assumes no upload transformations (we don't apply any on upload).
    /// </summary>
    private static (string publicId, ResourceType resourceType) ParsePublicId(string url)
    {
        const string uploadMarker = "/upload/";
        var idx = url.IndexOf(uploadMarker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
            return (string.Empty, ResourceType.Image);

        var resourceType =
            url.Contains("/raw/upload/", StringComparison.OrdinalIgnoreCase) ? ResourceType.Raw :
            url.Contains("/video/upload/", StringComparison.OrdinalIgnoreCase) ? ResourceType.Video :
            ResourceType.Image;

        var afterUpload = url[(idx + uploadMarker.Length)..];

        var stop = afterUpload.IndexOfAny(new[] { '?', '#' });
        if (stop >= 0)
            afterUpload = afterUpload[..stop];

        var segments = afterUpload.Split('/');

        // Drop a leading version segment like "v1700000000".
        var skip = (segments.Length > 0 &&
                    segments[0].Length > 1 &&
                    segments[0][0] == 'v' &&
                    segments[0][1..].All(char.IsDigit)) ? 1 : 0;

        var publicId = string.Join('/', segments.Skip(skip));

        // image/video public_ids carry no extension; raw public_ids do.
        if (resourceType != ResourceType.Raw)
        {
            var lastDot = publicId.LastIndexOf('.');
            var lastSlash = publicId.LastIndexOf('/');
            if (lastDot > lastSlash)
                publicId = publicId[..lastDot];
        }

        return (publicId, resourceType);
    }

    private StoredFile ToStoredFile(RawUploadResult result, string fileName)
    {
        if (result.Error != null)
        {
            _logger.LogError("Cloudinary upload failed for {FileName}: {Error}", fileName, result.Error.Message);
            throw new InvalidOperationException($"Image upload failed: {result.Error.Message}");
        }

        var url = result.SecureUrl?.ToString();
        if (string.IsNullOrWhiteSpace(url))
            throw new InvalidOperationException("Cloudinary did not return a URL for the uploaded file.");

        return new StoredFile(url, result.PublicId);
    }
}
