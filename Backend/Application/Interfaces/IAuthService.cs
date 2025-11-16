
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
    Task<ApiResponse<AuthResponseDto>> GoogleLoginAsync(string googleToken);
    
    // Enhanced methods with ApiResponse
    Task<ApiResponse<AuthResponseDto>> RegisterVendorAsync(VendorRegistrationDto vendorDto);
    Task<ApiResponse<bool>> VerifyEmailAsync(string email, string verificationCode);
    Task<ApiResponse<bool>> RequestPasswordResetAsync(ForgotPasswordDto forgotPasswordDto);
    Task<ApiResponse<bool>> VerifyResetCodeAsync(VerifyResetCodeDto verifyResetCodeDto);
    Task<ApiResponse<bool>> ResetPasswordAsync(ResetPasswordDto resetPasswordDto);
}