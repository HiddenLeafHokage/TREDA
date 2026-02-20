namespace Application.DTOs.Message;

/// <summary>Vendor: pass BuyerId (+ optional ProductId). Buyer: pass VendorId (+ optional ProductId).</summary>
public class GetOrCreateConversationDto
{
    public string? VendorId { get; set; }
    public string? BuyerId { get; set; }
    public string? ProductId { get; set; }
}
