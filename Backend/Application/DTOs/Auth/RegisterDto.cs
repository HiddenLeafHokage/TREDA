
using System.ComponentModel.DataAnnotations;
using Domain.Enums;

namespace Application.DTOs.Auth;

public class RegisterDto
{
    [Required]
    [MaxLength(100)]
    public string FullName { get; set; } = string.Empty;
    
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
    
    public string? PhoneNumber { get; set; }
    public string? Location { get; set; }
    
    // For sellers
    public string? BusinessName { get; set; }
    public string? BusinessCategory { get; set; }
    public string? BusinessLogoUrl { get; set; }
    
    [Required]
    public UserType UserType { get; set; }
    
    [Required]
    [MinLength(6)]
    public string Password { get; set; } = string.Empty;
    
    [Required]
    [Compare("Password")]
    public string ConfirmPassword { get; set; } = string.Empty;
}