// API/Controllers/AuthController.cs
using API.Attributes;
using API.Helpers;
using Microsoft.AspNetCore.RateLimiting;
using Application.Constants;
using Application.DTOs.Auth;
using Application.DTOs.Common;
using Application.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
[EnableRateLimiting("auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly IFileStorageService _storage;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IAuthService authService, IFileStorageService storage, ILogger<AuthController> logger)
    {
        _authService = authService;
        _storage = storage;
        _logger = logger;
    }
    
    [HttpGet("check-email")]
    public async Task<ActionResult<ApiResponse<object>>> CheckEmail([FromQuery] string email)
    {
        if (string.IsNullOrWhiteSpace(email) || !email.Contains('@'))
            return BadRequest(ApiResponse<object>.ErrorResult("Provide a valid email address.", ResponseCodes.VALIDATION_ERROR));

        var exists = await _authService.EmailExistsAsync(email.Trim().ToLower());
        var data = (object)new { available = !exists };

        if (exists)
            return Conflict(ApiResponse<object>.ErrorResult("This email is already registered.", ResponseCodes.CONFLICT));

        return Ok(ApiResponse<object>.SuccessResult(data, "Email is available."));
    }

    [HttpGet("check-phone")]
    public async Task<ActionResult<ApiResponse<object>>> CheckPhone([FromQuery] string phoneNumber)
    {
        if (string.IsNullOrWhiteSpace(phoneNumber))
            return BadRequest(ApiResponse<object>.ErrorResult("Provide a valid phone number.", ResponseCodes.VALIDATION_ERROR));

        var exists = await _authService.PhoneExistsAsync(phoneNumber.Trim());
        var data = (object)new { available = !exists };

        if (exists)
            return Conflict(ApiResponse<object>.ErrorResult("This phone number is already linked to an account.", ResponseCodes.CONFLICT));

        return Ok(ApiResponse<object>.SuccessResult(data, "Phone number is available."));
    }

    /// <summary>
    /// Register a vendor. Send the fields as multipart/form-data, with an optional image file
    /// field "logo". If a logo is included it is uploaded and saved on the new account; if omitted,
    /// the vendor starts with a first-letter avatar (they can add a logo later via store-appearance).
    /// </summary>
    [HttpPost("register-vendor")]
    [Consumes("multipart/form-data")]
    public async Task<ActionResult<ApiResponse<AuthResponseDto>>> RegisterVendor(
        [FromForm] VendorRegistrationDto vendorDto,
        IFormFile? logo,
        CancellationToken cancellationToken = default)
    {
        var (logoError, logoStored) = await ImageUploadHelper.TryStoreAsync(logo, _storage, "logo", cancellationToken);
        if (logoError != null)
            return BadRequest(ApiResponse<AuthResponseDto>.ErrorResult(logoError, ResponseCodes.VALIDATION_ERROR));

        var result = await _authService.RegisterVendorAsync(vendorDto, logoStored?.Url);

        // If the account couldn't be created, don't leave the uploaded logo orphaned.
        if (result.Code is not (ResponseCodes.SUCCESS or ResponseCodes.CREATED))
            await _storage.DeleteAsync(logoStored?.PublicId, cancellationToken);

        return result.Code switch
        {
            ResponseCodes.SUCCESS or ResponseCodes.CREATED => Ok(result),
            ResponseCodes.CONFLICT => Conflict(result),
            ResponseCodes.VALIDATION_ERROR => BadRequest(result),
            _ => StatusCode(500, result)
        };
    }

    [HttpPost("verify-email")]
    public async Task<ActionResult<ApiResponse<bool>>> VerifyEmail(VerifyEmailDto verifyEmailDto)
    {
        var result = await _authService.VerifyEmailAsync(verifyEmailDto.Email, verifyEmailDto.VerificationCode);
        
        return result.Code switch
        {
            ResponseCodes.SUCCESS => Ok(result),
            ResponseCodes.NOT_FOUND => NotFound(result),
            ResponseCodes.VALIDATION_ERROR => BadRequest(result),
            _ => StatusCode(500, result)
        };
    }

    /// <summary>Resend email verification code (e.g. if user lost or deleted the first email).</summary>
    [HttpPost("resend-verification-email")]
    public async Task<ActionResult<ApiResponse<bool>>> ResendVerificationEmail(ResendVerificationEmailDto dto)
    {
        var result = await _authService.ResendVerificationEmailAsync(dto.Email);
        return Ok(result);
    }
    
    [HttpPost("login")]
    public async Task<ActionResult<ApiResponse<AuthResponseDto>>> Login(LoginDto loginDto)
    {
        var result = await _authService.LoginAsync(loginDto);
        
        return result.Code switch
        {
            ResponseCodes.SUCCESS    => Ok(result),
            ResponseCodes.UNAUTHORIZED  => Unauthorized(result),   // 401 — wrong credentials
            ResponseCodes.FORBIDDEN     => StatusCode(403, result), // 403 — email not verified
            ResponseCodes.VALIDATION_ERROR => BadRequest(result),
            _ => StatusCode(500, result)
        };
    }
    
    [HttpPost("forgot-password")]
    public async Task<ActionResult<ApiResponse<bool>>> ForgotPassword(ForgotPasswordDto forgotPasswordDto)
    {
        var result = await _authService.RequestPasswordResetAsync(forgotPasswordDto);
        
        // Always return success to prevent email enumeration
        return Ok(ApiResponse<bool>.SuccessResult(
            true,
            "If an account with this email exists, a password reset code has been sent."
        ));
    }
    
    [HttpPost("verify-reset-code")]
    public async Task<ActionResult<ApiResponse<bool>>> VerifyResetCode(VerifyResetCodeDto verifyResetCodeDto)
    {
        var result = await _authService.VerifyResetCodeAsync(verifyResetCodeDto);
        
        return result.Code switch
        {
            ResponseCodes.SUCCESS => Ok(result),
            ResponseCodes.VALIDATION_ERROR => BadRequest(result),
            _ => StatusCode(500, result)
        };
    }
    
    [HttpPost("reset-password")]
    public async Task<ActionResult<ApiResponse<bool>>> ResetPassword(ResetPasswordDto resetPasswordDto)
    {
        var result = await _authService.ResetPasswordAsync(resetPasswordDto);
        
        return result.Code switch
        {
            ResponseCodes.SUCCESS => Ok(result),
            ResponseCodes.VALIDATION_ERROR => BadRequest(result),
            _ => StatusCode(500, result)
        };
    }
    
    [HttpPost("refresh-token")]
    public async Task<ActionResult<ApiResponse<AuthResponseDto>>> RefreshToken(RefreshTokenDto refreshTokenDto)
    {
        var result = await _authService.RefreshTokenAsync(refreshTokenDto.Token, refreshTokenDto.RefreshToken);
        
        return result.Code switch
        {
            ResponseCodes.SUCCESS => Ok(result),
            ResponseCodes.UNAUTHORIZED => Unauthorized(result),
            _ => StatusCode(500, result)
        };
    }

}

