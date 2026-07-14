using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Subscription;
using Application.Interfaces;
using Application.Subscriptions;
using Domain.Entities;
using Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Persistence.Data;

namespace Application.Services;

public class SubscriptionService : ISubscriptionService
{
    private readonly TredaDbContext _context;
    private readonly IVendorNotificationService _notifications;

    public SubscriptionService(TredaDbContext context, IVendorNotificationService notifications)
    {
        _context = context;
        _notifications = notifications;
    }

    public async Task<ApiResponse<SubscriptionStatusDto>> GetForVendorAsync(string vendorId)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == vendorId && u.UserType == UserType.Vendor);
        if (user == null)
            return ApiResponse<SubscriptionStatusDto>.ErrorResult("Vendor not found.", ResponseCodes.NOT_FOUND);

        return ApiResponse<SubscriptionStatusDto>.SuccessResult(await BuildStatusAsync(user));
    }

    public async Task<ApiResponse<SubscriptionStatusDto>> SetByEmailAsync(SetSubscriptionDto dto)
    {
        if (!Enum.TryParse<SubscriptionTier>(dto.Tier, ignoreCase: true, out var tier))
            return ApiResponse<SubscriptionStatusDto>.ErrorResult(
                "Invalid tier. Use Free, Silver, Gold or Premium.", ResponseCodes.VALIDATION_ERROR);

        var email = dto.VendorEmail.Trim();
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email && u.UserType == UserType.Vendor);
        if (user == null)
            return ApiResponse<SubscriptionStatusDto>.ErrorResult("Vendor not found.", ResponseCodes.NOT_FOUND);

        user.SubscriptionTier = tier;
        user.SubscriptionExpiresAt = tier == SubscriptionTier.Free
            ? null
            : DateTime.UtcNow.AddDays(Math.Max(1, dto.DurationDays));
        user.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        await _notifications.NotifySubscriptionChangedAsync(user.Id, tier, user.SubscriptionExpiresAt);

        return ApiResponse<SubscriptionStatusDto>.SuccessResult(
            await BuildStatusAsync(user),
            tier == SubscriptionTier.Free ? "Subscription cleared (Free)." : $"Vendor set to {tier} until {user.SubscriptionExpiresAt:yyyy-MM-dd}.");
    }

    private async Task<SubscriptionStatusDto> BuildStatusAsync(User user)
    {
        var productsUsed = await _context.Products.CountAsync(p => p.VendorId == user.Id);
        var promotedUsed = await _context.Products.CountAsync(p => p.VendorId == user.Id && p.IsPromoted);
        var plan = SubscriptionPlans.For(user);

        static int? Cap(int v) => v == SubscriptionPlans.Unlimited ? null : v;

        return new SubscriptionStatusDto
        {
            Tier = user.SubscriptionTier.ToString(),
            EffectiveTier = SubscriptionPlans.EffectiveTier(user).ToString(),
            IsPaid = SubscriptionPlans.IsPaid(user),
            ExpiresAt = user.SubscriptionExpiresAt,
            ProductsUsed = productsUsed,
            MaxProducts = Cap(plan.MaxProducts),
            PromotedUsed = promotedUsed,
            MaxPromotedProducts = Cap(plan.MaxPromotedProducts),
            CanPromote = plan.CanPromote
        };
    }
}
