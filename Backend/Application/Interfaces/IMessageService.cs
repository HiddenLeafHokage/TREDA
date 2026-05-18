using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Message;

namespace Application.Interfaces;

public interface IMessageService
{
    Task<ApiResponse<List<ConversationDto>>> GetVendorConversationsAsync(string vendorId);
    Task<ApiResponse<List<MessageDto>>> GetMessagesAsync(string conversationId, string userId, int page = 1, int pageSize = AppConstants.DefaultMessagePageSize);
    Task<ApiResponse<MessageDto>> SendMessageAsync(string conversationId, string senderId, SendMessageDto dto);
    Task<ApiResponse<ConversationDto>> GetOrCreateConversationAsync(string vendorId, string buyerId, string? productId = null);
    Task<ApiResponse<ConversationDto>> GetOrCreateGuestConversationAsync(GuestStartConversationDto dto);
    Task<ApiResponse<MessageDto>> SendGuestMessageAsync(string conversationId, GuestSendMessageDto dto);
    Task<ApiResponse<List<MessageDto>>> GetGuestMessagesAsync(string conversationId, string guestEmail, int page = 1, int pageSize = AppConstants.DefaultMessagePageSize);
}
