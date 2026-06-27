// Application/Services/AuthService.cs
using System.Security.Claims;
using Application.Constants;
using Application.DTOs.Auth;
using Application.DTOs.Category;
using Application.DTOs.Common;
using Application.DTOs.Vendor;
using Application.Helpers;
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
    private readonly IFileStorageService _storage;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        TredaDbContext context,
        ITokenService tokenService,
        IEmailService emailService,
        IFileStorageService storage,
        ILogger<AuthService> logger)
    {
        _context = context;
        _tokenService = tokenService;
        _emailService = emailService;
        _storage = storage;
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
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerDto.Password, workFactor: 10),
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
            
            var authResponse = await BuildAuthResponseAsync(
                user, token, refreshToken, DateTime.UtcNow.AddMinutes(60));

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
                    ResponseCodes.FORBIDDEN
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
            
            var authResponse = await BuildAuthResponseAsync(
                user, token, refreshToken, DateTime.UtcNow.AddMinutes(tokenExpirationMinutes));

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
            
            var authResponse = await BuildAuthResponseAsync(
                user, newToken, newRefreshToken, DateTime.UtcNow.AddMinutes(60));

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
    
    public async Task<ApiResponse<AuthResponseDto>> RegisterVendorAsync(VendorRegistrationDto vendorDto, string? logoUrl = null)
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
            
            var selectedCategoryIds = await ValidateAndNormalizeCategoryIdsAsync(vendorDto.BusinessCategoryIds);
            if (selectedCategoryIds.Count == 0)
            {
                return ApiResponse<AuthResponseDto>.ErrorResult(
                    "Select at least one valid business category.",
                    ResponseCodes.VALIDATION_ERROR);
            }

            var businessCategory = await BuildBusinessCategoryDisplayAsync(selectedCategoryIds);

            // Create new seller user with complete profile
            var user = new User
            {
                Id = Guid.NewGuid().ToString(),
                FullName = vendorDto.FullName,
                Email = vendorDto.Email,
                PhoneNumber = vendorDto.PhoneNumber,
                BusinessName = vendorDto.BusinessName,
                BusinessSlug = await GenerateUniqueBusinessSlugAsync(vendorDto.BusinessName),
                BusinessCategory = businessCategory,
                BusinessCategoryIds = selectedCategoryIds,
                BusinessLocation = vendorDto.BusinessLocation,
                ShopDescription = vendorDto.ShopDescription,
                // logoUrl is set only by the multipart register-vendor-with-logo endpoint (already
                // uploaded to storage). Otherwise null → vendor starts with a first-letter avatar.
                BusinessLogoUrl = logoUrl,
                BusinessLogoUpdatedAt = logoUrl != null ? DateTime.UtcNow : null,
                CAC_RC_Number = vendorDto.CAC_RC_Number,
                DeliveryMethod = vendorDto.DeliveryMethod,
                UserType = UserType.Vendor,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(vendorDto.Password, workFactor: 10),
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                IsActive = true,
                EmailVerified = false
            };
            
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            
            // Generate email verification code — non-fatal: user can resend if this fails
            try { await GenerateAndSendEmailVerificationCode(user.Id); }
            catch (Exception ex) { _logger.LogError(ex, "Failed to send verification email to {Email} — user can use resend-verification-email", user.Email); }

            // Send welcome email — non-fatal
            try { await _emailService.SendWelcomeEmailAsync(user.Email, user.BusinessName); }
            catch (Exception ex) { _logger.LogError(ex, "Failed to send welcome email to {Email}", user.Email); }
            
            // Generate tokens
            var token = _tokenService.GenerateToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken();
            
            // Save refresh token
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await _context.SaveChangesAsync();
            
            var authResponse = await BuildAuthResponseAsync(
                user, token, refreshToken, DateTime.UtcNow.AddMinutes(60));

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

            if (user.EmailVerified)
                return ApiResponse<bool>.SuccessResult(true, "Email is already verified. You can log in.");

            // Trim so trailing spaces / pasted whitespace never cause a false mismatch.
            var code = verificationCode?.Trim() ?? string.Empty;
            if (string.IsNullOrEmpty(code))
                return ApiResponse<bool>.ErrorResult(
                    "Enter the verification code sent to your email.",
                    ResponseCodes.VALIDATION_ERROR);

            // Look up by code alone (newest first) so we can report the exact reason it failed
            // instead of a single "invalid or expired" message that hides what went wrong.
            var verificationToken = await _context.EmailVerificationTokens
                .Where(evt => evt.UserId == user.Id && evt.Token == code)
                .OrderByDescending(evt => evt.CreatedAt)
                .FirstOrDefaultAsync();

            if (verificationToken == null)
                return ApiResponse<bool>.ErrorResult(
                    "Incorrect verification code. It is 6 digits and can start with 0 — enter it exactly as shown.",
                    ResponseCodes.VALIDATION_ERROR);

            if (verificationToken.IsUsed)
                return ApiResponse<bool>.ErrorResult(
                    "This code has already been used. Request a new one with resend-verification-email.",
                    ResponseCodes.VALIDATION_ERROR);

            if (verificationToken.ExpiresAt <= DateTime.UtcNow)
                return ApiResponse<bool>.ErrorResult(
                    "This code has expired. Request a new one with resend-verification-email.",
                    ResponseCodes.VALIDATION_ERROR);

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
            var resetCode = _tokenService.GenerateRandomCode();
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
            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(resetPasswordDto.NewPassword, workFactor: 10);
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
        // Invalidate any previous unused codes so only the newest code works — avoids
        // confusion when a user requests several codes and tries an older one.
        var previousCodes = await _context.EmailVerificationTokens
            .Where(t => t.UserId == userId && !t.IsUsed)
            .ToListAsync();
        foreach (var previous in previousCodes)
            previous.IsUsed = true;

        var verificationCode = _tokenService.GenerateRandomCode();
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
    
    /// <summary>
    /// Builds the auth response (login/register/refresh) including the display fields the frontend
    /// needs right after login: logo URL, first-letter avatar, and the vendor's selected categories.
    /// </summary>
    private async Task<AuthResponseDto> BuildAuthResponseAsync(User user, string token, string refreshToken, DateTime expiration)
    {
        var categoryIds = user.BusinessCategoryIds;
        var categories = categoryIds.Count == 0
            ? new List<CategoryDto>()
            : await _context.ProductCategories
                .Where(c => categoryIds.Contains(c.Id))
                .OrderBy(c => c.DisplayOrder)
                .Select(c => new CategoryDto
                {
                    Id = c.Id,
                    Name = c.Name,
                    Slug = c.Slug,
                    Description = c.Description,
                    DisplayOrder = c.DisplayOrder
                })
                .ToListAsync();

        return new AuthResponseDto
        {
            Id = user.Id,
            FullName = user.FullName,
            Email = user.Email,
            UserType = user.UserType.ToString(),
            EmailVerified = user.EmailVerified,
            BusinessName = user.BusinessName,
            BusinessLogoUrl = user.BusinessLogoUrl,
            DisplayInitial = VendorBrandingHelper.GetDisplayInitial(user),
            BusinessCategories = categories,
            ProfileCompleted = IsVendorProfileComplete(user),
            Token = token,
            RefreshToken = refreshToken,
            Expiration = expiration
        };
    }

    private bool IsVendorProfileComplete(User user)
    {
        if (user.UserType != UserType.Vendor) return true;
        
        return user.BusinessCategoryIds.Count > 0 &&
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
            return ApiResponse<VendorProfileDto>.ErrorResult("Vendor not found.", ResponseCodes.NOT_FOUND);

        var branding = VendorBrandingHelper.MapBranding(user);
        var dto = new VendorProfileDto
        {
            Id = user.Id,
            FullName = user.FullName,
            Email = user.Email,
            PhoneNumber = user.PhoneNumber,
            BusinessName = user.BusinessName,
            BusinessSlug = user.BusinessSlug,
            BusinessCategory = user.BusinessCategory,
            BusinessCategoryIds = user.BusinessCategoryIds,
            BusinessLocation = user.BusinessLocation,
            ShopDescription = user.ShopDescription,
            BusinessLogoUrl = branding.BusinessLogoUrl,
            BusinessCoverPhotoUrl = branding.BusinessCoverPhotoUrl,
            Branding = branding,
            CAC_RC_Number = user.CAC_RC_Number,
            DeliveryMethod = user.DeliveryMethod,
            EmailVerified = user.EmailVerified,
            CreatedAt = user.CreatedAt,
            UpdatedAt = user.UpdatedAt
        };

        return ApiResponse<VendorProfileDto>.SuccessResult(dto, "Profile retrieved successfully.");
    }

    public async Task<ApiResponse<bool>> UpdateVendorProfileAsync(string userId, UpdateVendorProfileDto dto)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id == userId && u.UserType == UserType.Vendor);

        if (user == null)
            return ApiResponse<bool>.ErrorResult("Vendor not found.", ResponseCodes.NOT_FOUND);

        var logoError = TryUpdateBrandingAsset(
            user,
            dto.BusinessLogoUrl,
            user.BusinessLogoUrl,
            user.BusinessLogoUpdatedAt,
            (url, ts) =>
            {
                user.BusinessLogoUrl = url;
                user.BusinessLogoUpdatedAt = ts;
            },
            "Shop logo");
        if (logoError != null)
            return logoError;

        var coverError = TryUpdateBrandingAsset(
            user,
            dto.BusinessCoverPhotoUrl,
            user.BusinessCoverPhotoUrl,
            user.BusinessCoverPhotoUpdatedAt,
            (url, ts) =>
            {
                user.BusinessCoverPhotoUrl = url;
                user.BusinessCoverPhotoUpdatedAt = ts;
            },
            "Cover photo");
        if (coverError != null)
            return coverError;

        var selectedCategoryIds = await ValidateAndNormalizeCategoryIdsAsync(dto.BusinessCategoryIds);
        if (selectedCategoryIds.Count == 0)
        {
            return ApiResponse<bool>.ErrorResult(
                "Select at least one valid business category.",
                ResponseCodes.VALIDATION_ERROR);
        }

        user.BusinessCategoryIds = selectedCategoryIds;
        user.BusinessCategory = await BuildBusinessCategoryDisplayAsync(selectedCategoryIds);
        user.BusinessLocation = dto.BusinessLocation;
        user.ShopDescription = dto.ShopDescription;
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

    public async Task<ApiResponse<VendorBrandingDto>> UpdateVendorBrandingAsync(string userId, UpdateVendorBrandingDto dto)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Id == userId && u.UserType == UserType.Vendor);

        if (user == null)
            return ApiResponse<VendorBrandingDto>.ErrorResult("Vendor not found.", ResponseCodes.NOT_FOUND);

        // Remember what we'll be replacing so we can delete the orphaned files after a successful save.
        var previousLogoUrl = user.BusinessLogoUrl;
        var previousCoverUrl = user.BusinessCoverPhotoUrl;

        if (dto.BusinessLogoUrl != null)
        {
            var logoError = TryUpdateBrandingAsset(
                user,
                dto.BusinessLogoUrl,
                user.BusinessLogoUrl,
                user.BusinessLogoUpdatedAt,
                (url, ts) =>
                {
                    user.BusinessLogoUrl = url;
                    user.BusinessLogoUpdatedAt = ts;
                },
                "Shop logo");
            if (logoError != null)
                return ApiResponse<VendorBrandingDto>.ErrorResult(logoError.Message, logoError.Code);
        }

        if (dto.BusinessCoverPhotoUrl != null)
        {
            var coverError = TryUpdateBrandingAsset(
                user,
                dto.BusinessCoverPhotoUrl,
                user.BusinessCoverPhotoUrl,
                user.BusinessCoverPhotoUpdatedAt,
                (url, ts) =>
                {
                    user.BusinessCoverPhotoUrl = url;
                    user.BusinessCoverPhotoUpdatedAt = ts;
                },
                "Cover photo");
            if (coverError != null)
                return ApiResponse<VendorBrandingDto>.ErrorResult(coverError.Message, coverError.Code);
        }

        user.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        // Best-effort cleanup of replaced assets (only when the URL actually changed).
        if (!string.IsNullOrWhiteSpace(previousLogoUrl) &&
            !string.Equals(previousLogoUrl, user.BusinessLogoUrl, StringComparison.OrdinalIgnoreCase))
            await _storage.DeleteByUrlAsync(previousLogoUrl);

        if (!string.IsNullOrWhiteSpace(previousCoverUrl) &&
            !string.Equals(previousCoverUrl, user.BusinessCoverPhotoUrl, StringComparison.OrdinalIgnoreCase))
            await _storage.DeleteByUrlAsync(previousCoverUrl);

        return ApiResponse<VendorBrandingDto>.SuccessResult(
            VendorBrandingHelper.MapBranding(user),
            "Branding updated successfully.");
    }

    public async Task<bool> EmailExistsAsync(string email)
        => await _context.Users.AnyAsync(u => u.Email == email);

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

    private async Task<List<string>> ValidateAndNormalizeCategoryIdsAsync(IEnumerable<string>? categoryIds)
    {
        var normalized = categoryIds?
            .Select(c => c?.Trim())
            .Where(c => !string.IsNullOrWhiteSpace(c))
            .Select(c => ProductCategorySeed.LegacyIdMap.TryGetValue(c!, out var mapped) ? mapped : c!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList() ?? new List<string>();

        if (normalized.Count == 0)
            return new List<string>();

        var activeIds = await _context.ProductCategories
            .Where(c => c.IsActive && normalized.Contains(c.Id))
            .Select(c => c.Id)
            .ToListAsync();

        return normalized
            .Where(id => activeIds.Contains(id, StringComparer.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private async Task<string> BuildBusinessCategoryDisplayAsync(IReadOnlyCollection<string> categoryIds)
    {
        var names = await _context.ProductCategories
            .Where(c => categoryIds.Contains(c.Id))
            .OrderBy(c => c.DisplayOrder)
            .Select(c => c.Name)
            .ToListAsync();

        return string.Join(", ", names);
    }

    private async Task<string> GenerateUniqueBusinessSlugAsync(string businessName)
    {
        var baseSlug = VendorSlugHelper.CreateSlug(businessName);
        var slug = baseSlug;
        var suffix = 2;

        while (await _context.Users.AnyAsync(u => u.BusinessSlug == slug))
        {
            slug = $"{baseSlug}-{suffix}";
            suffix++;
        }

        return slug;
    }

    private static ApiResponse<bool>? TryUpdateBrandingAsset(
        User user,
        string? newUrl,
        string? currentUrl,
        DateTime? lastUpdatedAt,
        Action<string?, DateTime?> apply,
        string assetLabel)
    {
        var normalizedNew = string.IsNullOrWhiteSpace(newUrl) ? null : newUrl.Trim();
        var normalizedCurrent = string.IsNullOrWhiteSpace(currentUrl) ? null : currentUrl.Trim();

        if (string.Equals(normalizedNew, normalizedCurrent, StringComparison.OrdinalIgnoreCase))
            return null;

        if (normalizedNew != null)
        {
            var urlError = VendorBrandingHelper.ValidateBrandingImageUrl(normalizedNew, assetLabel);
            if (urlError != null)
                return ApiResponse<bool>.ErrorResult(urlError, ResponseCodes.VALIDATION_ERROR);
        }

        if (normalizedCurrent == null)
        {
            apply(normalizedNew, normalizedNew != null ? DateTime.UtcNow : null);
            return null;
        }

        var reference = lastUpdatedAt ?? user.CreatedAt;
        var allowedAfter = reference.AddMonths(AppConstants.VendorBrandingChangeCooldownMonths);
        if (DateTime.UtcNow < allowedAfter)
        {
            return ApiResponse<bool>.ErrorResult(
                $"{assetLabel} can only be changed every {AppConstants.VendorBrandingChangeCooldownMonths} months. You can change it again after {allowedAfter:yyyy-MM-dd} UTC.",
                ResponseCodes.VALIDATION_ERROR);
        }

        apply(normalizedNew, DateTime.UtcNow);
        return null;
    }
}
