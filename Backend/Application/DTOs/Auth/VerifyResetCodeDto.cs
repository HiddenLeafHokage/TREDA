using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Application.DTOs.Auth
{
    public class VerifyResetCodeDto
    {
        [Required(ErrorMessage = "Email Address is required")]
    [EmailAddress(ErrorMessage = "Invalid email address format")]
    public string Email { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Reset code is required")]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "Reset code must be 6 digits")]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "Reset code must be 6 digits")]
    public string ResetCode { get; set; } = string.Empty;
        
    }
}