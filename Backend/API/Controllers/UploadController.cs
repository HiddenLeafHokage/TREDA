using API.Attributes;
using Microsoft.AspNetCore.RateLimiting;
using Application.Constants;
using Application.DTOs.Common;
using Application.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UploadController : ControllerBase
{
    private readonly IFileStorageService _storage;
    private readonly ILogger<UploadController> _logger;

    public UploadController(IFileStorageService storage, ILogger<UploadController> logger)
    {
        _storage = storage;
        _logger = logger;
    }

    /// <summary>Upload a file (image or PDF). Allowed: JPEG, PNG, GIF, WebP, PDF. Max 5 MB.</summary>
    [HttpPost]
    [SimpleAuthorize]
    [EnableRateLimiting("uploads")]
    [RequestSizeLimit(AppConstants.MaxUploadSizeBytes)]
    public async Task<ActionResult<ApiResponse<UploadResultDto>>> Upload(IFormFile? file, CancellationToken cancellationToken = default)
    {
        if (file == null || file.Length == 0)
            return BadRequest(ApiResponse<UploadResultDto>.ErrorResult("No file or empty file.", ResponseCodes.VALIDATION_ERROR));

        var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (string.IsNullOrEmpty(ext) || !AppConstants.AllowedUploadExtensions.Contains(ext))
            return BadRequest(ApiResponse<UploadResultDto>.ErrorResult(
                $"Allowed types: {string.Join(", ", AppConstants.AllowedUploadExtensions)}. Max size: 5 MB.",
                ResponseCodes.VALIDATION_ERROR));

        if (file.Length > AppConstants.MaxUploadSizeBytes)
            return BadRequest(ApiResponse<UploadResultDto>.ErrorResult("File too large. Max 5 MB.", ResponseCodes.VALIDATION_ERROR));

        try
        {
            await using var stream = file.OpenReadStream();
            var stored = await _storage.UploadAsync(stream, file.FileName, file.ContentType, cancellationToken);

            return Ok(ApiResponse<UploadResultDto>.SuccessResult(
                new UploadResultDto { Url = stored.Url, RelativeUrl = stored.PublicId, FileName = file.FileName },
                "File uploaded successfully."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Upload failed for {FileName}", file.FileName);
            return StatusCode(500, ApiResponse<UploadResultDto>.ErrorResult("Upload failed.", ResponseCodes.SERVER_ERROR));
        }
    }

    /// <summary>Upload up to 5 images at once (e.g. product gallery). Same rules as single upload.</summary>
    [HttpPost("batch")]
    [SimpleAuthorize]
    [EnableRateLimiting("uploads")]
    [RequestSizeLimit(AppConstants.MaxUploadSizeBytes * AppConstants.MaxProductImagesPerProduct)]
    public async Task<ActionResult<ApiResponse<List<UploadResultDto>>>> UploadBatch(
        IFormFileCollection? files,
        CancellationToken cancellationToken = default)
    {
        if (files == null || files.Count == 0)
            return BadRequest(ApiResponse<List<UploadResultDto>>.ErrorResult("No files uploaded.", ResponseCodes.VALIDATION_ERROR));

        if (files.Count > AppConstants.MaxProductImagesPerProduct)
        {
            return BadRequest(ApiResponse<List<UploadResultDto>>.ErrorResult(
                $"You can upload at most {AppConstants.MaxProductImagesPerProduct} images per request.",
                ResponseCodes.VALIDATION_ERROR));
        }

        var results = new List<UploadResultDto>();
        var storedIds = new List<string>();

        try
        {
            foreach (var file in files)
            {
                if (file.Length == 0)
                    return BadRequest(ApiResponse<List<UploadResultDto>>.ErrorResult("One or more files are empty.", ResponseCodes.VALIDATION_ERROR));

                var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
                if (string.IsNullOrEmpty(ext) || !AppConstants.AllowedUploadExtensions.Contains(ext))
                {
                    return BadRequest(ApiResponse<List<UploadResultDto>>.ErrorResult(
                        $"Allowed types: {string.Join(", ", AppConstants.AllowedUploadExtensions)}. Max size per file: 5 MB.",
                        ResponseCodes.VALIDATION_ERROR));
                }

                if (file.Length > AppConstants.MaxUploadSizeBytes)
                    return BadRequest(ApiResponse<List<UploadResultDto>>.ErrorResult("One or more files exceed 5 MB.", ResponseCodes.VALIDATION_ERROR));

                await using var stream = file.OpenReadStream();
                var stored = await _storage.UploadAsync(stream, file.FileName, file.ContentType, cancellationToken);

                storedIds.Add(stored.PublicId);
                results.Add(new UploadResultDto
                {
                    Url = stored.Url,
                    RelativeUrl = stored.PublicId,
                    FileName = file.FileName
                });
            }

            return Ok(ApiResponse<List<UploadResultDto>>.SuccessResult(results, "Files uploaded successfully."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Batch upload failed");
            // Roll back any files already stored in this batch so we don't leave orphans.
            foreach (var id in storedIds)
                await _storage.DeleteAsync(id, cancellationToken);
            return StatusCode(500, ApiResponse<List<UploadResultDto>>.ErrorResult("Batch upload failed.", ResponseCodes.SERVER_ERROR));
        }
    }
}

public class UploadResultDto
{
    public string Url { get; set; } = string.Empty;
    public string RelativeUrl { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
}
