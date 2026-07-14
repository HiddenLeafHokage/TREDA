using Application.DTOs.Common;
using Application.DTOs.Subscription;

namespace Application.Interfaces;

public interface ISubscriptionService
{
    Task<ApiResponse<SubscriptionStatusDto>> GetForVendorAsync(string vendorId);

    /// <summary>Admin/test: set a vendor's tier + expiry by email. Real payment plugs in here later.</summary>
    Task<ApiResponse<SubscriptionStatusDto>> SetByEmailAsync(SetSubscriptionDto dto);
}
