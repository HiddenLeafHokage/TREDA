using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Message;
using Application.Interfaces;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Persistence.Data;

namespace Application.Services;

public class MessageService : IMessageService
{
    private readonly TredaDbContext _context;
    private readonly ILogger<MessageService> _logger;
    private readonly IVendorNotificationService _notifications;

    public MessageService(TredaDbContext context, ILogger<MessageService> logger, IVendorNotificationService notifications)
    {
        _context = context;
        _logger = logger;
        _notifications = notifications;
    }

    public async Task<ApiResponse<List<ConversationDto>>> GetVendorConversationsAsync(string vendorId)
    {
        var list = await _context.Conversations
            .Include(c => c.Buyer)
            .Include(c => c.Product)
            .Include(c => c.Messages)
            .Where(c => c.VendorId == vendorId)
            .OrderByDescending(c => c.UpdatedAt)
            .ToListAsync();

        var dtos = new List<ConversationDto>();
        foreach (var c in list)
        {
            var last = c.Messages.OrderByDescending(m => m.SentAt).FirstOrDefault();
            dtos.Add(new ConversationDto
            {
                Id = c.Id,
                BuyerId = c.BuyerId,
                BuyerName = c.Buyer?.FullName ?? c.GuestName ?? AppConstants.DefaultBuyerDisplayName,
                GuestEmail = c.GuestEmail,
                ProductId = c.ProductId,
                ProductName = c.Product?.Name,
                LastMessagePreview = last?.Content?.Length > AppConstants.MessagePreviewMaxLength
                    ? last.Content[..AppConstants.MessagePreviewMaxLength] + AppConstants.MessagePreviewSuffix
                    : last?.Content,
                LastMessageAt = last?.SentAt,
                UnreadCount = 0
            });
        }
        return ApiResponse<List<ConversationDto>>.SuccessResult(dtos);
    }

    public async Task<ApiResponse<List<MessageDto>>> GetMessagesAsync(string conversationId, string userId, int page = 1, int pageSize = 50)
    {
        var conv = await _context.Conversations.FirstOrDefaultAsync(c => c.Id == conversationId && (c.VendorId == userId || c.BuyerId == userId));
        if (conv == null)
            return ApiResponse<List<MessageDto>>.ErrorResult("Conversation not found.", ResponseCodes.NOT_FOUND);

        var list = await _context.Messages
            .Include(m => m.Sender)
            .Where(m => m.ConversationId == conversationId)
            .OrderByDescending(m => m.SentAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
        var dtos = list.Select(m => new MessageDto
        {
            Id = m.Id,
            ConversationId = m.ConversationId,
            SenderId = m.SenderId,
            SenderDisplayName = m.Sender?.FullName ?? m.GuestSenderName,
            Content = m.Content,
            SentAt = m.SentAt,
            IsFromCurrentUser = m.SenderId == userId
        }).OrderBy(m => m.SentAt).ToList();
        return ApiResponse<List<MessageDto>>.SuccessResult(dtos);
    }

    public async Task<ApiResponse<MessageDto>> SendMessageAsync(string conversationId, string senderId, SendMessageDto dto)
    {
        var conv = await _context.Conversations.FirstOrDefaultAsync(c => c.Id == conversationId && (c.VendorId == senderId || c.BuyerId == senderId));
        if (conv == null)
            return ApiResponse<MessageDto>.ErrorResult("Conversation not found.", ResponseCodes.NOT_FOUND);

        var msg = new Message
        {
            Id = Guid.NewGuid().ToString(),
            ConversationId = conversationId,
            SenderId = senderId,
            Content = dto.Content,
            SentAt = DateTime.UtcNow
        };
        _context.Messages.Add(msg);
        conv.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        if (senderId != conv.VendorId)
        {
            var preview = dto.Content.Length > 120 ? dto.Content[..120] + "…" : dto.Content;
            var senderName = await _context.Users.AsNoTracking().Where(u => u.Id == senderId).Select(u => u.FullName).FirstOrDefaultAsync();
            await _notifications.NotifyNewMessageFromBuyerAsync(conv.VendorId, conversationId, preview, senderName);
        }

        return ApiResponse<MessageDto>.SuccessResult(new MessageDto
        {
            Id = msg.Id,
            ConversationId = msg.ConversationId,
            SenderId = msg.SenderId,
            Content = msg.Content,
            SentAt = msg.SentAt,
            IsFromCurrentUser = msg.SenderId == senderId
        });
    }

    public async Task<ApiResponse<ConversationDto>> GetOrCreateConversationAsync(string vendorId, string buyerId, string? productId)
    {
        var conv = await _context.Conversations
            .Include(c => c.Buyer)
            .Include(c => c.Product)
            .FirstOrDefaultAsync(c => c.VendorId == vendorId && c.BuyerId == buyerId && c.ProductId == productId);
        if (conv != null)
            return ApiResponse<ConversationDto>.SuccessResult(MapConversation(conv));

        conv = new Conversation
        {
            Id = Guid.NewGuid().ToString(),
            VendorId = vendorId,
            BuyerId = buyerId,
            ProductId = productId,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        _context.Conversations.Add(conv);
        await _context.SaveChangesAsync();
        await _context.Entry(conv).Reference(c => c.Buyer).LoadAsync();
        await _context.Entry(conv).Reference(c => c.Product).LoadAsync();
        return ApiResponse<ConversationDto>.SuccessResult(MapConversation(conv));
    }

    public async Task<ApiResponse<ConversationDto>> GetOrCreateGuestConversationAsync(GuestStartConversationDto dto)
    {
        var vendorExists = await _context.Users.AnyAsync(u => u.Id == dto.VendorId);
        if (!vendorExists)
            return ApiResponse<ConversationDto>.ErrorResult("Vendor not found.", ResponseCodes.NOT_FOUND);
        if (!string.IsNullOrEmpty(dto.ProductId))
        {
            var productExists = await _context.Products.AnyAsync(p => p.Id == dto.ProductId && p.VendorId == dto.VendorId);
            if (!productExists)
                return ApiResponse<ConversationDto>.ErrorResult("Product not found.", ResponseCodes.NOT_FOUND);
        }

        var conv = await _context.Conversations
            .Include(c => c.Product)
            .FirstOrDefaultAsync(c => c.VendorId == dto.VendorId && c.GuestEmail == dto.GuestEmail && c.ProductId == dto.ProductId);
        if (conv != null)
            return ApiResponse<ConversationDto>.SuccessResult(MapConversation(conv));

        conv = new Conversation
        {
            Id = Guid.NewGuid().ToString(),
            VendorId = dto.VendorId,
            BuyerId = null,
            GuestEmail = dto.GuestEmail,
            GuestName = dto.GuestName,
            ProductId = dto.ProductId,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        _context.Conversations.Add(conv);
        await _context.SaveChangesAsync();
        await _context.Entry(conv).Reference(c => c.Product).LoadAsync();
        return ApiResponse<ConversationDto>.SuccessResult(MapConversation(conv));
    }

    public async Task<ApiResponse<MessageDto>> SendGuestMessageAsync(string conversationId, GuestSendMessageDto dto)
    {
        var conv = await _context.Conversations.FirstOrDefaultAsync(c => c.Id == conversationId && c.GuestEmail == dto.GuestEmail);
        if (conv == null)
            return ApiResponse<MessageDto>.ErrorResult("Conversation not found or email does not match.", ResponseCodes.NOT_FOUND);

        var msg = new Message
        {
            Id = Guid.NewGuid().ToString(),
            ConversationId = conversationId,
            SenderId = null,
            GuestSenderEmail = dto.GuestEmail,
            GuestSenderName = conv.GuestName,
            Content = dto.Content,
            SentAt = DateTime.UtcNow
        };
        _context.Messages.Add(msg);
        conv.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        var guestPreview = dto.Content.Length > 120 ? dto.Content[..120] + "…" : dto.Content;
        await _notifications.NotifyNewMessageFromBuyerAsync(conv.VendorId, conversationId, guestPreview, conv.GuestName);

        return ApiResponse<MessageDto>.SuccessResult(new MessageDto
        {
            Id = msg.Id,
            ConversationId = msg.ConversationId,
            SenderId = null,
            SenderDisplayName = msg.GuestSenderName,
            Content = msg.Content,
            SentAt = msg.SentAt,
            IsFromCurrentUser = true
        });
    }

    public async Task<ApiResponse<List<MessageDto>>> GetGuestMessagesAsync(string conversationId, string guestEmail, int page = 1, int pageSize = 50)
    {
        var conv = await _context.Conversations.FirstOrDefaultAsync(c => c.Id == conversationId && c.GuestEmail == guestEmail);
        if (conv == null)
            return ApiResponse<List<MessageDto>>.ErrorResult("Conversation not found or email does not match.", ResponseCodes.NOT_FOUND);

        var list = await _context.Messages
            .Include(m => m.Sender)
            .Where(m => m.ConversationId == conversationId)
            .OrderByDescending(m => m.SentAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
        var dtos = list.Select(m => new MessageDto
        {
            Id = m.Id,
            ConversationId = m.ConversationId,
            SenderId = m.SenderId,
            SenderDisplayName = m.Sender?.FullName ?? m.GuestSenderName,
            Content = m.Content,
            SentAt = m.SentAt,
            IsFromCurrentUser = m.GuestSenderEmail == guestEmail
        }).OrderBy(m => m.SentAt).ToList();
        return ApiResponse<List<MessageDto>>.SuccessResult(dtos);
    }

    private static ConversationDto MapConversation(Conversation c)
    {
        return new ConversationDto
        {
            Id = c.Id,
            BuyerId = c.BuyerId,
            BuyerName = c.Buyer?.FullName ?? c.GuestName ?? AppConstants.DefaultBuyerDisplayName,
            GuestEmail = c.GuestEmail,
            ProductId = c.ProductId,
            ProductName = c.Product?.Name,
            LastMessageAt = null,
            UnreadCount = 0
        };
    }
}
