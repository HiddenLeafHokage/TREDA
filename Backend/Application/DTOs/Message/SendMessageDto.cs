using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.Message;

public class SendMessageDto
{
    [Required]
    [MaxLength(2000)]
    public string Content { get; set; } = string.Empty;
}
