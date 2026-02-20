namespace Application.DTOs.Wallet;

public class WalletTransactionDto
{
    public string Id { get; set; } = string.Empty;
    public decimal Amount { get; set; }
    public string Type { get; set; } = string.Empty; // Credit / Debit
    public string Description { get; set; } = string.Empty;
    public string? Reference { get; set; }
    public DateTime CreatedAt { get; set; }
}
