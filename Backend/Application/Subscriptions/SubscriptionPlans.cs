using Domain.Entities;
using Domain.Enums;

namespace Application.Subscriptions;

/// <summary>What a tier is allowed to do. int.MaxValue means "unlimited".</summary>
public record SubscriptionPlan(
    SubscriptionTier Tier,
    int MaxProducts,
    int MaxPendingOrdersViewable,
    int MaxPromotedProducts,
    bool CanPromote,
    bool StoreRankedHigh,
    bool EligibleForTopStore);

/// <summary>
/// The ONE place every gate reads from. Change a number here, not ten endpoints. Gates are binary
/// free-vs-paid today (all paid tiers share values), but the table is keyed per-tier so Silver/Gold/
/// Premium can diverge later with no other code changes.
/// </summary>
public static class SubscriptionPlans
{
    public const int Unlimited = int.MaxValue;

    private static readonly IReadOnlyDictionary<SubscriptionTier, SubscriptionPlan> Plans =
        new Dictionary<SubscriptionTier, SubscriptionPlan>
        {
            [SubscriptionTier.Free] = new(
                SubscriptionTier.Free,
                MaxProducts: 3,
                MaxPendingOrdersViewable: 3,
                MaxPromotedProducts: 0,
                CanPromote: false,
                StoreRankedHigh: false,
                EligibleForTopStore: false),

            [SubscriptionTier.Silver] = Paid(SubscriptionTier.Silver),
            [SubscriptionTier.Gold] = Paid(SubscriptionTier.Gold),
            [SubscriptionTier.Premium] = Paid(SubscriptionTier.Premium),
        };

    private static SubscriptionPlan Paid(SubscriptionTier tier) => new(
        tier,
        MaxProducts: Unlimited,
        MaxPendingOrdersViewable: Unlimited,
        MaxPromotedProducts: 5,
        CanPromote: true,
        StoreRankedHigh: true,
        EligibleForTopStore: true);

    /// <summary>The tier actually in effect now — an expired paid tier falls back to Free.</summary>
    public static SubscriptionTier EffectiveTier(User user) =>
        user.SubscriptionTier != SubscriptionTier.Free &&
        user.SubscriptionExpiresAt.HasValue &&
        user.SubscriptionExpiresAt.Value > DateTime.UtcNow
            ? user.SubscriptionTier
            : SubscriptionTier.Free;

    public static SubscriptionPlan For(User user) => Plans[EffectiveTier(user)];

    public static SubscriptionPlan For(SubscriptionTier tier) => Plans[tier];

    public static bool IsPaid(User user) => EffectiveTier(user) != SubscriptionTier.Free;
}
