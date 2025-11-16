// Domain/Entities/User.cs
using System.ComponentModel.DataAnnotations;
using Domain.Enums;

namespace Domain.Entities;

public class User
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    
    [Required]
    [MaxLength(100)]
    public string FullName { get; set; } = string.Empty;
    
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
    
    public string? PhoneNumber { get; set; }
    // Business/Seller specific fields
    public string? BusinessName { get; set; }
    public string? BusinessCategory { get; set; }
    public string? BusinessLocation { get; set; } // City/State
    public string? ShopDescription { get; set; }
    public string? BusinessLogoUrl { get; set; }
    public string? CAC_RC_Number { get; set; }
    public DeliveryMethod? DeliveryMethod { get; set; }
    [Required]
    public UserType UserType { get; set; }
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public bool IsActive { get; set; } = true;
    public bool EmailVerified { get; set; } = false;
    
    // Authentication
    public string? PasswordHash { get; set; }
    public string? GoogleId { get; set; }
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiryTime { get; set; }
    // Navigation properties
    public virtual ICollection<PasswordResetToken> PasswordResetTokens { get; set; } = new List<PasswordResetToken>();
    public virtual ICollection<EmailVerificationToken> EmailVerificationTokens { get; set; } = new List<EmailVerificationToken>();
}

