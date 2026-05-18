using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Message;

public class GuestSendMessageDto
{
    [Required]
    [EmailAddress]
    [MaxLength(256)]
    public string GuestEmail { get; set; } = string.Empty;

    [Required]
    [MaxLength(2000)]
    public string Content { get; set; } = string.Empty;
}
