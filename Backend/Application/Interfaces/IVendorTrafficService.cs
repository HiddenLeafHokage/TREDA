using Domain.Enums;

namespace Application.Interfaces;

public interface IVendorTrafficService
{
    Task RecordProductViewAsync(string vendorId, string? productId);
    Task RecordEngagementAsync(string vendorId, string? productId, VendorTrafficEventType type);
    Task RecordSearchExposureAsync(IReadOnlyCollection<string> vendorIds, string searchTerm);
}
