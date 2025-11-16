// API/Controllers/AuthController.cs
using API.Attributes;
using Application.DTOs.Auth;
using Application.DTOs.Common;
using Application.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ILogger<AuthController> _logger;
    
    public AuthController(IAuthService authService, ILogger<AuthController> logger)
    {
        _authService = authService;
        _logger = logger;
    }
    
    [HttpGet("test")]
    public IActionResult Test()
    {
        var response = ApiResponse<object>.SuccessResult(new { 
            message = "Treda API is working!",
            timestamp = DateTime.UtcNow,
            version = "1.0.0"
        });
        
        return Ok(response);
    }
    
    [HttpPost("register-vendor")]
    public async Task<ActionResult<ApiResponse<AuthResponseDto>>> RegisterVendor(VendorRegistrationDto vendorDto)
    {
        var result = await _authService.RegisterVendorAsync(vendorDto);
        
        // Return appropriate HTTP status based on the response code
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
    
    [HttpPost("login")]
    public async Task<ActionResult<ApiResponse<AuthResponseDto>>> Login(LoginDto loginDto)
    {
        var result = await _authService.LoginAsync(loginDto);
        
        return result.Code switch
        {
            ResponseCodes.SUCCESS => Ok(result),
            ResponseCodes.UNAUTHORIZED => Unauthorized(result),
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

    [HttpPost("google-login")]
    public async Task<ActionResult<ApiResponse<AuthResponseDto>>> GoogleLogin(GoogleLoginDto googleLoginDto)
    {
        var result = await _authService.GoogleLoginAsync(googleLoginDto.GoogleToken);
        
        return result.Code switch
        {
            ResponseCodes.SUCCESS => Ok(result),
            ResponseCodes.SERVICE_UNAVAILABLE => StatusCode(501, result),
            _ => StatusCode(500, result)
        };
    }
    
    [SimpleAuthorize("Buyer", "Seller", "Admin")]
    [HttpGet("profile")]
    public ActionResult<ApiResponse<object>> GetProfile()
    {
        try
        {
            var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var userEmail = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
            var userName = User.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value;
            var userRole = User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;
            var emailVerified = User.FindFirst("EmailVerified")?.Value;
            var businessName = User.FindFirst("BusinessName")?.Value;
            
            var profileData = new {
                userId,
                userEmail,
                userName,
                userRole,
                emailVerified = bool.TryParse(emailVerified, out var verified) ? verified : false,
                businessName
            };
            
            return Ok(ApiResponse<object>.SuccessResult(profileData, "Profile retrieved successfully!"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving user profile");
            return StatusCode(500, ApiResponse<object>.ErrorResult("An error occurred while retrieving profile."));
        }
    }
}

