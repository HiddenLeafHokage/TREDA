namespace Application.DTOs.Wallet;

public class WalletBalanceDto
{
    public decimal Balance { get; set; }
    public string VendorId { get; set; } = string.Empty;
}
