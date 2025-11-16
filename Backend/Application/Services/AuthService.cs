// Application/Services/AuthService.cs
using System.Security.Claims;
using Application.DTOs.Auth;
using Application.DTOs.Common;
using Application.Interfaces;
using Domain.Entities;
using Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Persistence.Data;

namespace Application.Services;

public class AuthService : IAuthService
{
    private readonly TredaDbContext _context;
    private readonly ITokenService _tokenService;
    private readonly IEmailService _emailService;
    private readonly ITokenGenerator _tokenGenerator;
    private readonly ILogger<AuthService> _logger;
    
    public AuthService(
        TredaDbContext context, 
        ITokenService tokenService, 
        IEmailService emailService,
        ITokenGenerator tokenGenerator,
        ILogger<AuthService> logger)
    {
        _context = context;
        _tokenService = tokenService;
        _emailService = emailService;
        _tokenGenerator = tokenGenerator;
        _logger = logger;
    }
    
    public async Task<ApiResponse<AuthResponseDto>> RegisterAsync(RegisterDto registerDto)
    {
        try
        {
            // Check if user already exists
            if (await _context.Users.AnyAsync(u => u.Email == registerDto.Email))
            {
                return ApiResponse<AuthResponseDto>.ErrorResult(
                    "User with this email already exists.", 
                    ResponseCodes.CONFLICT
                );
            }
            
            // Validate user type - prevent admin registration
            if (registerDto.UserType == UserType.Admin)
            {
                return ApiResponse<AuthResponseDto>.ErrorResult(
                    "Admin registration is not allowed.",
                    ResponseCodes.FORBIDDEN
                );
            }
            
            // Create new user
            var user = new User
            {
                Id = Guid.NewGuid().ToString(),
                FullName = registerDto.FullName,
                Email = registerDto.Email,
                PhoneNumber = registerDto.PhoneNumber,
                // Location = registerDto.Location,
                BusinessName = registerDto.BusinessName,
                BusinessCategory = registerDto.BusinessCategory,
                BusinessLogoUrl = registerDto.BusinessLogoUrl,
                UserType = registerDto.UserType,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerDto.Password),
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                IsActive = true,
                EmailVerified = false
            };
            
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            
            // Generate tokens
            var token = _tokenService.GenerateToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();
            
            // Save refresh token
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _context.SaveChangesAsync();
            
            var authResponse = new AuthResponseDto
            {
                Id = user.Id,
                FullName = user.FullName,
                Email = user.Email,
                UserType = user.UserType.ToString(),
                EmailVerified = user.EmailVerified,
                BusinessName = user.BusinessName,
                ProfileCompleted = IsSellerProfileComplete(user),
                Token = token,
                RefreshToken = refreshToken,
                Expiration = DateTime.UtcNow.AddMinutes(60)
            };
            
            return ApiResponse<AuthResponseDto>.SuccessResult(authResponse, "Registration successful!");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during registration for email: {Email}", registerDto.Email);
            return ApiResponse<AuthResponseDto>.ErrorResult(
                "An error occurred during registration.",
                ResponseCodes.SERVER_ERROR
            );
        }
    }
    
    public async Task<ApiResponse<AuthResponseDto>> LoginAsync(LoginDto loginDto)
    {
        try
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == loginDto.Email && u.IsActive);
                
            if (user == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.PasswordHash))
            {
                return ApiResponse<AuthResponseDto>.ErrorResult(
                    "Invalid email address or password.",
                    ResponseCodes.UNAUTHORIZED
                );
            }
            
            // Update token expiration based on RememberMe
            var tokenExpirationMinutes = loginDto.RememberMe ? 43200 : 60; // 30 days vs 1 hour
            
            // Generate tokens
            var token = _tokenService.GenerateToken(user, tokenExpirationMinutes);
            var refreshToken = _tokenService.GenerateRefreshToken();
            
            // Save refresh token
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = loginDto.RememberMe ? 
                DateTime.UtcNow.AddDays(30) : DateTime.UtcNow.AddDays(7);
                
            await _context.SaveChangesAsync();
            
            var authResponse = new AuthResponseDto
            {
                Id = user.Id,
                FullName = user.FullName,
                Email = user.Email,
                UserType = user.UserType.ToString(),
                EmailVerified = user.EmailVerified,
                BusinessName = user.BusinessName,
                ProfileCompleted = IsSellerProfileComplete(user),
                Token = token,
                RefreshToken = refreshToken,
                Expiration = DateTime.UtcNow.AddMinutes(tokenExpirationMinutes)
            };
            
            return ApiResponse<AuthResponseDto>.SuccessResult(authResponse, "Login successful!");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login for email: {Email}", loginDto.Email);
            return ApiResponse<AuthResponseDto>.ErrorResult(
                "An error occurred during login.",
                ResponseCodes.SERVER_ERROR
            );
        }
    }
    
    public async Task<ApiResponse<AuthResponseDto>> RefreshTokenAsync(string token, string refreshToken)
    {
        try
        {
            var principal = _tokenService.GetPrincipalFromExpiredToken(token);
            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            
            if (string.IsNullOrEmpty(userId))
            {
                return ApiResponse<AuthResponseDto>.ErrorResult(
                    "Invalid token",
                    ResponseCodes.UNAUTHORIZED
                );
            }
            
            var user = await _context.Users.FindAsync(userId);
            if (user == null || !_tokenService.ValidateRefreshToken(user, refreshToken))
            {
                return ApiResponse<AuthResponseDto>.ErrorResult(
                    "Invalid refresh token",
                    ResponseCodes.UNAUTHORIZED
                );
            }
            
            // Generate new tokens
            var newToken = _tokenService.GenerateToken(user);
            var newRefreshToken = _tokenService.GenerateRefreshToken();
            
            // Update user with new refresh token
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            user.UpdatedAt = DateTime.UtcNow;
            
            await _context.SaveChangesAsync();
            
            var authResponse = new AuthResponseDto
            {
                Id = user.Id,
                FullName = user.FullName,
                Email = user.Email,
                UserType = user.UserType.ToString(),
                EmailVerified = user.EmailVerified,
                BusinessName = user.BusinessName,
                ProfileCompleted = IsSellerProfileComplete(user),
                Token = newToken,
                RefreshToken = newRefreshToken,
                Expiration = DateTime.UtcNow.AddMinutes(60)
            };
            
            return ApiResponse<AuthResponseDto>.SuccessResult(authResponse, "Token refreshed successfully!");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing token");
            return ApiResponse<AuthResponseDto>.ErrorResult(
                "An error occurred while refreshing token.",
                ResponseCodes.SERVER_ERROR
            );
        }
    }
    
    public async Task<ApiResponse<bool>> RevokeTokenAsync(string userId)
    {
        try
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult(
                    "User not found.",
                    ResponseCodes.NOT_FOUND
                );
            }
            
            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;
            user.UpdatedAt = DateTime.UtcNow;
            
            await _context.SaveChangesAsync();
            
            return ApiResponse<bool>.SuccessResult(true, "Token revoked successfully!");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking token for user: {UserId}", userId);
            return ApiResponse<bool>.ErrorResult(
                "An error occurred while revoking token.",
                ResponseCodes.SERVER_ERROR
            );
        }
    }
    
    public Task<ApiResponse<AuthResponseDto>> GoogleLoginAsync(string googleToken)
    {
        return Task.FromResult(ApiResponse<AuthResponseDto>.ErrorResult(
            "Google authentication is not yet implemented.",
            ResponseCodes.SERVICE_UNAVAILABLE
        ));
    }
    
    public async Task<ApiResponse<AuthResponseDto>> RegisterVendorAsync(VendorRegistrationDto vendorDto)
    {
        try
        {
            // Check if user already exists
            if (await _context.Users.AnyAsync(u => u.Email == vendorDto.Email))
            {
                return ApiResponse<AuthResponseDto>.ErrorResult(
                    "User with this email address already exists.", 
                    ResponseCodes.CONFLICT
                );
            }
            
            // Create new seller user with complete profile
            var user = new User
            {
                Id = Guid.NewGuid().ToString(),
                FullName = vendorDto.FullName,
                Email = vendorDto.Email,
                PhoneNumber = vendorDto.PhoneNumber,
                BusinessName = vendorDto.BusinessName,
                BusinessCategory = vendorDto.BusinessCategory,
                BusinessLocation = vendorDto.BusinessLocation,
                ShopDescription = vendorDto.ShopDescription,
                BusinessLogoUrl = vendorDto.BusinessLogoUrl,
                CAC_RC_Number = vendorDto.CAC_RC_Number,
                DeliveryMethod = vendorDto.DeliveryMethod,
                UserType = UserType.Seller,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(vendorDto.Password),
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                IsActive = true,
                EmailVerified = false
            };
            
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            
            // Generate email verification code
            await GenerateAndSendEmailVerificationCode(user.Id);
            
            // Send welcome email
            await _emailService.SendWelcomeEmailAsync(user.Email, user.BusinessName);
            
            // Generate tokens
            var token = _tokenService.GenerateToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();
            
            // Save refresh token
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _context.SaveChangesAsync();
            
            var authResponse = new AuthResponseDto
            {
                Id = user.Id,
                FullName = user.FullName,
                Email = user.Email,
                UserType = user.UserType.ToString(),
                EmailVerified = user.EmailVerified,
                BusinessName = user.BusinessName,
                ProfileCompleted = true,
                Token = token,
                RefreshToken = refreshToken,
                Expiration = DateTime.UtcNow.AddMinutes(60)
            };
            
            return ApiResponse<AuthResponseDto>.SuccessResult(
                authResponse, 
                "Vendor registration successful! Please check your email for verification code."
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during vendor registration for email: {Email}", vendorDto.Email);
            return ApiResponse<AuthResponseDto>.ErrorResult(
                "An error occurred during registration. Please try again.",
                ResponseCodes.SERVER_ERROR
            );
        }
    }
    
    public async Task<ApiResponse<bool>> VerifyEmailAsync(string email, string verificationCode)
    {
        try
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == email && u.IsActive);
                
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult(
                    "User not found.",
                    ResponseCodes.NOT_FOUND
                );
            }
            
            var verificationToken = await _context.EmailVerificationTokens
                .FirstOrDefaultAsync(evt => 
                    evt.UserId == user.Id && 
                    evt.Token == verificationCode &&
                    !evt.IsUsed &&
                    evt.ExpiresAt > DateTime.UtcNow);
                    
            if (verificationToken == null)
            {
                return ApiResponse<bool>.ErrorResult(
                    "Invalid or expired verification code.",
                    ResponseCodes.VALIDATION_ERROR
                );
            }
            
            // Mark email as verified
            user.EmailVerified = true;
            user.UpdatedAt = DateTime.UtcNow;
            
            // Mark token as used
            verificationToken.IsUsed = true;
            
            await _context.SaveChangesAsync();
            
            return ApiResponse<bool>.SuccessResult(
                true,
                "Email verified successfully!"
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying email for: {Email}", email);
            return ApiResponse<bool>.ErrorResult(
                "An error occurred during email verification.",
                ResponseCodes.SERVER_ERROR
            );
        }
    }
    
    public async Task<ApiResponse<bool>> RequestPasswordResetAsync(ForgotPasswordDto forgotPasswordDto)
    {
        try
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == forgotPasswordDto.Email && u.IsActive);
                
            if (user == null)
            {
                // Don't reveal that email doesn't exist for security
                return ApiResponse<bool>.SuccessResult(
                    true,
                    "If an account with this email exists, a password reset code has been sent."
                );
            }
            
            // Generate reset token
            var resetCode = _tokenGenerator.GenerateRandomCode();
            var resetToken = new PasswordResetToken
            {
                UserId = user.Id,
                Token = resetCode,
                ExpiresAt = DateTime.UtcNow.AddHours(1), // 1 hour expiry
                IsUsed = false
            };
            
            _context.PasswordResetTokens.Add(resetToken);
            await _context.SaveChangesAsync();
            
            // Send reset code via email
            await _emailService.SendPasswordResetCodeAsync(user.Email, resetCode);
            
            return ApiResponse<bool>.SuccessResult(
                true,
                "If an account with this email exists, a password reset code has been sent."
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending password reset to: {Email}", forgotPasswordDto.Email);
            // Still return success to prevent email enumeration
            return ApiResponse<bool>.SuccessResult(
                true,
                "If an account with this email exists, a password reset code has been sent."
            );
        }
    }
    
    public async Task<ApiResponse<bool>> VerifyResetCodeAsync(VerifyResetCodeDto verifyResetCodeDto)
    {
        try
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == verifyResetCodeDto.Email && u.IsActive);
                
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult(
                    "Invalid or expired reset code.",
                    ResponseCodes.VALIDATION_ERROR
                );
            }
            
            var resetToken = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(prt => 
                    prt.UserId == user.Id && 
                    prt.Token == verifyResetCodeDto.ResetCode &&
                    !prt.IsUsed &&
                    prt.ExpiresAt > DateTime.UtcNow);
                    
            if (resetToken != null)
            {
                return ApiResponse<bool>.SuccessResult(
                    true,
                    "Reset code verified successfully."
                );
            }
            else
            {
                return ApiResponse<bool>.ErrorResult(
                    "Invalid or expired reset code.",
                    ResponseCodes.VALIDATION_ERROR
                );
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying reset code for: {Email}", verifyResetCodeDto.Email);
            return ApiResponse<bool>.ErrorResult(
                "An error occurred while verifying reset code.",
                ResponseCodes.SERVER_ERROR
            );
        }
    }
    
    public async Task<ApiResponse<bool>> ResetPasswordAsync(ResetPasswordDto resetPasswordDto)
    {
        try
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == resetPasswordDto.Email && u.IsActive);
                
            if (user == null)
            {
                return ApiResponse<bool>.ErrorResult(
                    "Invalid reset code or email.",
                    ResponseCodes.VALIDATION_ERROR
                );
            }
            
            var resetToken = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(prt => 
                    prt.UserId == user.Id && 
                    prt.Token == resetPasswordDto.ResetCode &&
                    !prt.IsUsed &&
                    prt.ExpiresAt > DateTime.UtcNow);
                    
            if (resetToken == null)
            {
                return ApiResponse<bool>.ErrorResult(
                    "Invalid reset code or email.",
                    ResponseCodes.VALIDATION_ERROR
                );
            }
            
            // Update password
            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(resetPasswordDto.NewPassword);
            user.UpdatedAt = DateTime.UtcNow;
            
            // Mark token as used
            resetToken.IsUsed = true;
            
            await _context.SaveChangesAsync();
            
            return ApiResponse<bool>.SuccessResult(
                true,
                "Password has been reset successfully. You can now login with your new password."
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resetting password for: {Email}", resetPasswordDto.Email);
            return ApiResponse<bool>.ErrorResult(
                "An error occurred while resetting password.",
                ResponseCodes.SERVER_ERROR
            );
        }
    }
    
    private async Task GenerateAndSendEmailVerificationCode(string userId)
    {
        var verificationCode = _tokenGenerator.GenerateRandomCode();
        var verificationToken = new EmailVerificationToken
        {
            UserId = userId,
            Token = verificationCode,
            ExpiresAt = DateTime.UtcNow.AddHours(24), // 24 hours expiry
            IsUsed = false
        };
        
        _context.EmailVerificationTokens.Add(verificationToken);
        await _context.SaveChangesAsync();
        
        var user = await _context.Users.FindAsync(userId);
        if (user != null)
        {
            await _emailService.SendEmailVerificationCodeAsync(user.Email, verificationCode);
        }
    }
    
    private bool IsSellerProfileComplete(User user)
    {
        if (user.UserType != UserType.Seller) return true;
        
        return !string.IsNullOrEmpty(user.BusinessCategory) &&
               !string.IsNullOrEmpty(user.BusinessLocation) &&
               !string.IsNullOrEmpty(user.ShopDescription) &&
               !string.IsNullOrEmpty(user.CAC_RC_Number) &&
               user.DeliveryMethod.HasValue;
    }
}