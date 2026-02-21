using Application.Constants;
using Application.DTOs.Common;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UploadController : ControllerBase
{
    private readonly IWebHostEnvironment _env;
    private readonly ILogger<UploadController> _logger;

    public UploadController(IWebHostEnvironment env, ILogger<UploadController> logger)
    {
        _env = env;
        _logger = logger;
    }

    /// <summary>Upload a file (image or PDF). Allowed: JPEG, PNG, GIF, WebP, PDF. Max 5 MB.</summary>
    [HttpPost]
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

        var uploadsDir = Path.Combine(_env.ContentRootPath, "wwwroot", "uploads");
        Directory.CreateDirectory(uploadsDir);

        var safeName = $"{Guid.NewGuid():N}{ext}";
        var filePath = Path.Combine(uploadsDir, safeName);

        try
        {
            await using (var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, useAsync: true))
                await file.CopyToAsync(stream, cancellationToken);

            var url = $"/uploads/{safeName}";
            return Ok(ApiResponse<UploadResultDto>.SuccessResult(
                new UploadResultDto { Url = url, FileName = file.FileName },
                "File uploaded successfully."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Upload failed for {FileName}", file.FileName);
            if (System.IO.File.Exists(filePath))
                System.IO.File.Delete(filePath);
            return StatusCode(500, ApiResponse<UploadResultDto>.ErrorResult("Upload failed.", ResponseCodes.SERVER_ERROR));
        }
    }
}

public class UploadResultDto
{
    public string Url { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
}
