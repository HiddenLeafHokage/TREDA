using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

using Domain.Enums;

namespace Application.DTOs.Auth
{
    public class CompleteShopProfileDto
    {
         [Required(ErrorMessage = "User ID is required")]
    public string UserId { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Business category is required")]
    public string BusinessCategory { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Business location is required")]
    public string BusinessLocation { get; set; } = string.Empty; // City/State
    
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