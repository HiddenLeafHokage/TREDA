
using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Auth;
public class LoginDto
{
  [Required(ErrorMessage = "Email Address is required")]
    [EmailAddress(ErrorMessage = "Invalid email address format")]
    public string Email { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = string.Empty;
    
    public bool RememberMe { get; set; } = false;
}