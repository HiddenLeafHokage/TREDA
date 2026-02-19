using API.Attributes;
using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Message;
using Application.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class MessagesController : ControllerBase
{
    private readonly IMessageService _messageService;
    private readonly ILogger<MessagesController> _logger;

    public MessagesController(IMessageService messageService, ILogger<MessagesController> logger)
    {
        _messageService = messageService;
        _logger = logger;
    }

    private string? UserId => User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    [HttpGet("conversations")]
    [SimpleAuthorize(AppConstants.Roles.Vendor, AppConstants.Roles.Admin)]
    public async Task<ActionResult<ApiResponse<List<ConversationDto>>>> GetVendorConversations()
    {
        if (string.IsNullOrEmpty(UserId))
            return Unauthorized(ApiResponse<List<ConversationDto>>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _messageService.GetVendorConversationsAsync(UserId);
        return Ok(result);
    }

    [HttpGet("conversations/{conversationId}/messages")]
    [SimpleAuthorize(AppConstants.Roles.Buyer, AppConstants.Roles.Vendor, AppConstants.Roles.Admin)]
    public async Task<ActionResult<ApiResponse<List<MessageDto>>>> GetMessages(string conversationId, [FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        if (string.IsNullOrEmpty(UserId))
            return Unauthorized(ApiResponse<List<MessageDto>>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _messageService.GetMessagesAsync(conversationId, UserId, page, pageSize);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        return Ok(result);
    }

    [HttpPost("conversations/{conversationId}/messages")]
    [SimpleAuthorize(AppConstants.Roles.Buyer, AppConstants.Roles.Vendor, AppConstants.Roles.Admin)]
    public async Task<ActionResult<ApiResponse<MessageDto>>> SendMessage(string conversationId, [FromBody] SendMessageDto dto)
    {
        if (string.IsNullOrEmpty(UserId))
            return Unauthorized(ApiResponse<MessageDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _messageService.SendMessageAsync(conversationId, UserId, dto);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        return Ok(result);
    }

    [HttpPost("conversations")]
    [SimpleAuthorize(AppConstants.Roles.Buyer, AppConstants.Roles.Vendor, AppConstants.Roles.Admin)]
    public async Task<ActionResult<ApiResponse<ConversationDto>>> GetOrCreateConversation([FromBody] GetOrCreateConversationDto dto)
    {
        if (string.IsNullOrEmpty(UserId))
            return Unauthorized(ApiResponse<ConversationDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        string vendorId, buyerId;
        if (dto.VendorId == UserId && !string.IsNullOrEmpty(dto.BuyerId))
        {
            vendorId = dto.VendorId; buyerId = dto.BuyerId;
        }
        else if (dto.BuyerId == UserId && !string.IsNullOrEmpty(dto.VendorId))
        {
            vendorId = dto.VendorId!; buyerId = dto.BuyerId;
        }
        else
            return BadRequest(ApiResponse<ConversationDto>.ErrorResult("Provide VendorId (if you are buyer) or BuyerId (if you are vendor).", ResponseCodes.VALIDATION_ERROR));
        var result = await _messageService.GetOrCreateConversationAsync(vendorId, buyerId, dto.ProductId);
        return Ok(result);
    }
}
