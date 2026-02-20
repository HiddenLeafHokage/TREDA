using System.ComponentModel.DataAnnotations;

namespace Domain.Entities;

public class VendorWallet
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [Required]
    public string VendorId { get; set; } = string.Empty;
    public User? Vendor { get; set; }

    [Range(0, double.MaxValue)]
    public decimal Balance { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
