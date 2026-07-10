using Application.Constants;
using Application.Interfaces;

namespace API.Helpers;

/// <summary>
/// Shared validation + storage for optional image files that arrive inside a multipart request
/// (the logo on register-vendor, the logo/cover on store-appearance).
/// </summary>
public static class ImageUploadHelper
{
    /// <summary>
    /// Validates and stores <paramref name="file"/>.
    /// Returns (null, null) when no file was sent, (error, null) when the file is invalid,
    /// and (null, stored) on success.
    /// </summary>
    public static async Task<(string? Error, StoredFile? Stored)> TryStoreAsync(
        IFormFile? file,
        IFileStorageService storage,
        string fieldLabel,
        CancellationToken cancellationToken = default)
    {
        if (file is null || file.Length == 0)
            return (null, null);

        var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (string.IsNullOrEmpty(ext) || !AppConstants.AllowedUploadExtensions.Contains(ext))
            return ($"Allowed {fieldLabel} types: {string.Join(", ", AppConstants.AllowedUploadExtensions)}.", null);

        if (file.Length > AppConstants.MaxUploadSizeBytes)
            return ($"{fieldLabel} is too large. Max 5 MB.", null);

        await using var stream = file.OpenReadStream();
        var stored = await storage.UploadAsync(stream, file.FileName, file.ContentType, cancellationToken);
        return (null, stored);
    }
}
