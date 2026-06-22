namespace Application.Interfaces;

/// <summary>
/// Abstraction over where uploaded files (logos, cover photos, product images) physically live.
/// Business code depends only on this contract — never on Cloudinary, S3, or local disk directly.
/// Swap the implementation in Program.cs to migrate providers without touching controllers or services.
/// </summary>
public interface IFileStorageService
{
    /// <summary>
    /// Stores a file and returns a permanent, publicly reachable absolute URL.
    /// </summary>
    /// <param name="content">The file content stream.</param>
    /// <param name="fileName">Original file name (used for extension/MIME hints only).</param>
    /// <param name="contentType">MIME type of the file, e.g. "image/jpeg".</param>
    Task<StoredFile> UploadAsync(Stream content, string fileName, string contentType, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a previously stored file by its provider identifier. No-op when null/empty or already gone.
    /// Use this right after an upload when you still hold the fresh <see cref="StoredFile.PublicId"/>.
    /// </summary>
    /// <param name="publicId">The provider identifier returned in <see cref="StoredFile.PublicId"/>.</param>
    Task DeleteAsync(string? publicId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a previously stored file given its public URL. No-op when null/empty, already gone,
    /// or the URL does not belong to this provider. Use this to clean up replaced/deleted assets
    /// when only the stored URL (not the publicId) is known.
    /// </summary>
    Task DeleteByUrlAsync(string? url, CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of storing a file.
/// <para><see cref="Url"/> — the permanent absolute URL to serve to clients.</para>
/// <para><see cref="PublicId"/> — provider-specific handle used to delete the file later.</para>
/// </summary>
public sealed record StoredFile(string Url, string PublicId);
