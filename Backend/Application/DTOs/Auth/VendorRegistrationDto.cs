using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using Domain.Enums;

namespace Application.DTOs.Auth
{
    public class VendorRegistrationDto
    {
        // Basic Information
    [Required(ErrorMessage = "Full name is required")]
    [MaxLength(100, ErrorMessage = "Full name cannot exceed 100 characters")]
    public string FullName { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Business/Shop name is required")]
    [MaxLength(200, ErrorMessage = "Business name cannot exceed 200 characters")]
    public string BusinessName { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Email Address is required")]
    [EmailAddress(ErrorMessage = "Invalid email address format")]
    public string Email { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Phone number is required")]
    [Phone(ErrorMessage = "Invalid phone number format")]
    public string PhoneNumber { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Password is required")]
    [MinLength(8, ErrorMessage = "Password must be at least 8 characters")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$", 
        ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")]
    public string Password { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Please confirm your password")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;
    
    // Business Details
    [Required(ErrorMessage = "Business category is required")]
    public string BusinessCategory { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Business location is required")]
    public string BusinessLocation { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Shop description is required")]
    [MaxLength(1000, ErrorMessage = "Shop description cannot exceed 1000 characters")]
    public string ShopDescription { get; set; } = string.Empty;
    
    public string? BusinessLogoUrl { get; set; }
    
    [Required(ErrorMessage = "Delivery method is required")]
    public DeliveryMethod DeliveryMethod { get; set; }
    
    [Required(ErrorMessage = "CAC/RC Number is required")]
    [RegularExpression(@"^[A-Z]{2}-\d{6}$", ErrorMessage = "CAC/RC Number must be in format: RC-123456")]
    public string CAC_RC_Number { get; set; } = string.Empty;
    }
}