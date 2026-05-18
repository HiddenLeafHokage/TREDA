using Application.DTOs.Common;
using Application.DTOs.Vendor;

namespace Application.Interfaces;

public interface IVendorSearchService
{
    Task<ApiResponse<VendorSearchResultDto>> SearchAsync(string vendorId, string query, int perSectionLimit = 5);
}
