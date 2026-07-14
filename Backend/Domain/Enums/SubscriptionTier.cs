namespace Domain.Enums;

/// <summary>
/// Seller subscription plan. Gates are binary free-vs-paid for now, but each tier is modelled
/// separately so per-tier limits (e.g. product count) can differ later without changing the gates.
/// </summary>
public enum SubscriptionTier
{
    Free = 0,
    Silver = 1,
    Gold = 2,
    Premium = 3
}
