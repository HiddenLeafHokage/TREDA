
using Application.DTOs.Auth;
using Domain.Entities;
using Application.DTOs.Common;

namespace Application.Interfaces;
public interface IAuthService
{
    // Existing methods with ApiResponse wrapper
    Task<ApiResponse<AuthResponseDto>> RegisterAsync(RegisterDto registerDto);
    Task<ApiResponse<AuthResponseDto>> LoginAsync(LoginDto loginDto);
    Task<ApiResponse<AuthResponseDto>> RefreshTokenAsync(string token, string refreshToken);
    Task<ApiResponse<bool>> RevokeTokenAsync(string userId);
    
    // Enhanced methods with ApiResponse
    /// <summary>Registers a vendor. Pass <paramref name="logoUrl"/> (already uploaded) to set the shop logo at sign-up.</summary>
    Task<ApiResponse<AuthResponseDto>> RegisterVendorAsync(VendorRegistrationDto vendorDto, string? logoUrl = null);
    Task<ApiResponse<bool>> VerifyEmailAsync(string email, string verificationCode);
    Task<ApiResponse<bool>> ResendVerificationEmailAsync(string email);
    Task<ApiResponse<bool>> RequestPasswordResetAsync(ForgotPasswordDto forgotPasswordDto);
    Task<ApiResponse<bool>> VerifyResetCodeAsync(VerifyResetCodeDto verifyResetCodeDto);
    Task<ApiResponse<bool>> ResetPasswordAsync(ResetPasswordDto resetPasswordDto);

    Task<ApiResponse<Application.DTOs.Vendor.VendorProfileDto>> GetVendorProfileAsync(string userId);
    Task<ApiResponse<bool>> UpdateVendorProfileAsync(string userId, Application.DTOs.Vendor.UpdateVendorProfileDto dto);
    /// <summary>Set the shop logo and/or cover. null = leave unchanged. Logo has a 6-month cooldown; cover does not.</summary>
    Task<ApiResponse<Application.DTOs.Vendor.VendorBrandingDto>> UpdateVendorBrandingAsync(string userId, string? logoUrl, string? coverUrl);
    Task<bool> EmailExistsAsync(string email);
    Task<bool> PhoneExistsAsync(string phoneNumber);
}
