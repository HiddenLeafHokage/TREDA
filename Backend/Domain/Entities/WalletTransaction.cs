using System.ComponentModel.DataAnnotations;
using Domain.Enums;

namespace Domain.Entities;

public class WalletTransaction
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string VendorId { get; set; } = string.Empty;

    public decimal Amount { get; set; } // Positive = credit, Negative = debit
    public WalletTransactionType Type { get; set; }

    [MaxLength(500)]
    public string Description { get; set; } = string.Empty;

    [MaxLength(200)]
    public string? Reference { get; set; } // e.g. ProductId for "Treda Ads"

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
