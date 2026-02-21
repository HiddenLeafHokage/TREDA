// Application/Services/AuthService.cs
using System.Security.Claims;
using Application.Constants;
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
                ProfileCompleted = IsVendorProfileComplete(user),
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

            // Real-world flow: verify email before login
            if (!user.EmailVerified)
            {
                return ApiResponse<AuthResponseDto>.ErrorResult(
                    "Please verify your email before logging in. Check your inbox for the code, or use resend verification.",
                    ResponseCodes.VALIDATION_ERROR
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
                ProfileCompleted = IsVendorProfileComplete(user),
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
                ProfileCompleted = IsVendorProfileComplete(user),
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
            // Check if user already exists (email)
            if (await _context.Users.AnyAsync(u => u.Email == vendorDto.Email))
            {
                return ApiResponse<AuthResponseDto>.ErrorResult(
                    "User with this email address already exists.", 
                    ResponseCodes.CONFLICT
                );
            }

            // One phone number per account: check if phone already used by another user
            var normalizedPhone = NormalizePhone(vendorDto.PhoneNumber);
            if (!string.IsNullOrEmpty(normalizedPhone))
            {
                var existingPhones = await _context.Users.Where(u => u.PhoneNumber != null).Select(u => u.PhoneNumber).ToListAsync();
                if (existingPhones.Any(p => NormalizePhone(p) == normalizedPhone))
                {
                    return ApiResponse<AuthResponseDto>.ErrorResult(
                        "This phone number is already linked to another account.",
                        ResponseCodes.CONFLICT
                    );
                }
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
                UserType = UserType.Vendor,
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

    public async Task<ApiResponse<bool>> ResendVerificationEmailAsync(string email)
    {
        try
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == email && u.IsActive);

            if (user == null)
            {
                // Don't reveal whether email exists
                return ApiResponse<bool>.SuccessResult(
                    true,
                    "If an account with this email exists, a new verification code has been sent."
                );
            }

            if (user.EmailVerified)
            {
                return ApiResponse<bool>.SuccessResult(true, "Email is already verified. You can log in.");
            }

            await GenerateAndSendEmailVerificationCode(user.Id);
            return ApiResponse<bool>.SuccessResult(
                true,
                "A new verification code has been sent. It expires in 45 minutes."
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resending verification email for: {Email}", email);
            return ApiResponse<bool>.SuccessResult(
                true,
                "If an account with this email exists, a new verification code has been sent."
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
            ExpiresAt = DateTime.UtcNow.AddMinutes(AppConstants.EmailVerificationExpiryMinutes),
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
    
    private bool IsVendorProfileComplete(User user)
    {
        if (user.UserType != UserType.Vendor) return true;
        
        return !string.IsNullOrEmpty(user.BusinessCategory) &&
               !string.IsNullOrEmpty(user.BusinessLocation) &&
               !string.IsNullOrEmpty(user.ShopDescription) &&
               !string.IsNullOrEmpty(user.CAC_RC_Number) &&
               user.DeliveryMethod.HasValue;
    }

    public async Task<ApiResponse<Application.DTOs.Vendor.VendorProfileDto>> GetVendorProfileAsync(string userId)
    {
        var user = await _context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == userId && u.UserType == UserType.Vendor);

        if (user == null)
            return ApiResponse<Application.DTOs.Vendor.VendorProfileDto>.ErrorResult("Vendor not found.", ResponseCodes.NOT_FOUND);

        var dto = new Application.DTOs.Vendor.VendorProfileDto
        {
            Id = user.Id,
            FullName = user.FullName,
            Email = user.Email,
            PhoneNumber = user.PhoneNumber,
            BusinessName = user.BusinessName,
            BusinessCategory = user.BusinessCategory,
            BusinessLocation = user.BusinessLocation,
            ShopDescription = user.ShopDescription,
            BusinessLogoUrl = user.BusinessLogoUrl,
            CAC_RC_Number = user.CAC_RC_Number,
            DeliveryMethod = user.DeliveryMethod,
            EmailVerified = user.EmailVerified,
            CreatedAt = user.CreatedAt,
            UpdatedAt = user.UpdatedAt
        };

        return ApiResponse<Application.DTOs.Vendor.VendorProfileDto>.SuccessResult(dto, "Profile retrieved successfully.");
    }

    public async Task<ApiResponse<bool>> UpdateVendorProfileAsync(string userId, Application.DTOs.Vendor.UpdateVendorProfileDto dto)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id == userId && u.UserType == UserType.Vendor);

        if (user == null)
            return ApiResponse<bool>.ErrorResult("Vendor not found.", ResponseCodes.NOT_FOUND);

        user.BusinessCategory = dto.BusinessCategory;
        user.BusinessLocation = dto.BusinessLocation;
        user.ShopDescription = dto.ShopDescription;
        user.BusinessLogoUrl = dto.BusinessLogoUrl;
        user.CAC_RC_Number = dto.CAC_RC_Number;
        user.DeliveryMethod = dto.DeliveryMethod;
        user.UpdatedAt = DateTime.UtcNow;

        if (dto.PhoneNumber != null)
        {
            var normalizedNew = NormalizePhone(dto.PhoneNumber);
            if (!string.IsNullOrEmpty(normalizedNew))
            {
                var otherPhones = await _context.Users.Where(u => u.Id != userId && u.PhoneNumber != null).Select(u => u.PhoneNumber).ToListAsync();
                if (otherPhones.Any(p => NormalizePhone(p) == normalizedNew))
                    return ApiResponse<bool>.ErrorResult("This phone number is already linked to another account.", ResponseCodes.CONFLICT);
                user.PhoneNumber = dto.PhoneNumber.Trim();
            }
            else
                user.PhoneNumber = dto.PhoneNumber;
        }

        await _context.SaveChangesAsync();
        return ApiResponse<bool>.SuccessResult(true, "Profile updated successfully.");
    }

    /// <summary>Normalize for uniqueness: digits only; leading 0 treated as Nigerian (+234).</summary>
    private static string? NormalizePhone(string? phone)
    {
        if (string.IsNullOrWhiteSpace(phone)) return null;
        var digits = new string(phone.Where(char.IsDigit).ToArray());
        if (digits.Length < 10) return null;
        if (digits.StartsWith("0") && digits.Length >= 10)
            digits = "234" + digits.TrimStart('0');
        else if (!digits.StartsWith("234") && digits.Length >= 10)
            digits = "234" + digits;
        return digits;
    }
}