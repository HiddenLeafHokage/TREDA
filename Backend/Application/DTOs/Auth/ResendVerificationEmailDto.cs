using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Auth;

public class ResendVerificationEmailDto
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    public string Email { get; set; } = string.Empty;
}
