using System.ComponentModel.DataAnnotations;
using Domain.Enums;

namespace Domain.Entities;

public class VendorTrafficEvent
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string VendorId { get; set; } = string.Empty;

    public VendorTrafficEventType EventType { get; set; }

    public string? ProductId { get; set; }

    [MaxLength(500)]
    public string? SearchTerm { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
