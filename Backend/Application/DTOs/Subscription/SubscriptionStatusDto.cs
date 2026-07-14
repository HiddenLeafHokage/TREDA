namespace Application.DTOs.Subscription;

/// <summary>A vendor's current plan + usage, so the frontend can show "3/3 products — subscribe to add more".</summary>
public class SubscriptionStatusDto
{
    public string Tier { get; set; } = "Free";           // the tier stored on the account
    public string EffectiveTier { get; set; } = "Free";  // after the expiry check (expired paid → Free)
    public bool IsPaid { get; set; }
    public DateTime? ExpiresAt { get; set; }

    public int ProductsUsed { get; set; }
    public int? MaxProducts { get; set; }          // null = unlimited
    public int PromotedUsed { get; set; }
    public int? MaxPromotedProducts { get; set; }  // null = unlimited
    public bool CanPromote { get; set; }
}
