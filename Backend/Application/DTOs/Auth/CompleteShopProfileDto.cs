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
    [RegularExpression(@"(?i)^(RC|CAC|BN|LLP|LP|IT)-\d{1,7}$", ErrorMessage = "CAC/RC Number must be in format: RC-1234567, CAC-1234567, BN-1234567, LLP-1234567, LP-1234567, or IT-1234567")]
    public string CAC_RC_Number { get; set; } = string.Empty;
        
    }
}
