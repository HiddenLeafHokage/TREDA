using Application.DTOs.Common;
using Application.DTOs.Message;
using Application.DTOs.Order;
using Application.DTOs.Product;

namespace Application.DTOs.Vendor;

public class VendorSearchResultDto
{
    public PagedListDto<ProductResponseDto> Products { get; set; } = new();
    public PagedListDto<OrderResponseDto> Orders { get; set; } = new();
    public PagedListDto<ConversationDto> Conversations { get; set; } = new();
    public string? GlobalEmptyMessage { get; set; }
}
