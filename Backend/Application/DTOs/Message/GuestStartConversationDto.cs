using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Message;

public class GuestStartConversationDto
{
    [Required]
    public string VendorId { get; set; } = string.Empty;

    public string? ProductId { get; set; }

    [Required]
    [MaxLength(200)]
    public string GuestName { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    [MaxLength(256)]
    public string GuestEmail { get; set; } = string.Empty;
}
