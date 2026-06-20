using Microsoft.AspNetCore.RateLimiting;
using Application.DTOs.Common;
using Application.DTOs.Message;
using Application.DTOs.Order;
using Application.DTOs.Product;
using Application.DTOs.Vendor;
using Application.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

/// <summary>Endpoints for buyers without registration: browse products, contact seller via chat, create order/invoice.</summary>
[ApiController]
[Route("api/public")]
[EnableRateLimiting("public")]
public class PublicController : ControllerBase
{
    private readonly IProductService _productService;
    private readonly IMessageService _messageService;
    private readonly IOrderService _orderService;

    public PublicController(IProductService productService, IMessageService messageService, IOrderService orderService)
    {
        _productService = productService;
        _messageService = messageService;
        _orderService = orderService;
    }

    /// <summary>List products for browsing (search, filter by category, pagination). No auth.</summary>
    [HttpGet("products")]
    public async Task<ActionResult<ApiResponse<List<ProductResponseDto>>>> ListProducts(
        [FromQuery] string? search,
        [FromQuery] string? categoryId,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20)
    {
        var result = await _productService.ListPublicAsync(search, categoryId, page, pageSize);
        return Ok(result);
    }

    /// <summary>List all public vendor shops for buyer storefront browsing. No auth.</summary>
    [HttpGet("vendors")]
    public async Task<ActionResult<ApiResponse<PagedListDto<VendorStoreListItemDto>>>> ListVendors(
        [FromQuery] string? search,
        [FromQuery] string? categoryId,
        [FromQuery] string? location,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20)
    {
        var result = await _productService.ListPublicVendorsAsync(search, categoryId, location, page, pageSize);
        return Ok(result);
    }

    /// <summary>Public vendor storefront by URL slug, e.g. /shop/delizz-supermarket. No auth.</summary>
    [HttpGet("vendors/by-slug/{slug}")]
    public async Task<ActionResult<ApiResponse<VendorPublicProfileDto>>> GetVendorStorefrontBySlug(
        string slug,
        [FromQuery] string? categoryId,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20)
    {
        var result = await _productService.GetPublicVendorProfileBySlugAsync(slug, categoryId, page, pageSize);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        return Ok(result);
    }

    /// <summary>Public vendor storefront: shop banner, logo, info, and paginated active products.</summary>
    [HttpGet("vendors/{vendorId}")]
    public async Task<ActionResult<ApiResponse<VendorPublicProfileDto>>> GetVendorStorefront(
        string vendorId,
        [FromQuery] string? categoryId,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20)
    {
        var result = await _productService.GetPublicVendorProfileAsync(vendorId, categoryId, page, pageSize);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        return Ok(result);
    }

    /// <summary>Get product by id with seller/vendor contact info. No auth.</summary>
    [HttpGet("products/{id}")]
    public async Task<ActionResult<ApiResponse<ProductWithVendorDto>>> GetProduct(string id)
    {
        var result = await _productService.GetPublicByIdAsync(id);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        return Ok(result);
    }

    /// <summary>Optional: record click-through or favourite for analytics (views are recorded on GET product detail).</summary>
    [HttpPost("products/{id}/engage")]
    public async Task<ActionResult<ApiResponse<bool>>> RecordEngagement(string id, [FromBody] ProductEngagementDto dto)
    {
        var result = await _productService.RecordPublicProductEngagementAsync(id, dto.EventType);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        if (result.Code == ResponseCodes.VALIDATION_ERROR) return BadRequest(result);
        return Ok(result);
    }

    /// <summary>Guest starts a conversation with seller (e.g. from product page). No auth.</summary>
    [HttpPost("conversations")]
    public async Task<ActionResult<ApiResponse<ConversationDto>>> StartConversation([FromBody] GuestStartConversationDto dto)
    {
        var result = await _messageService.GetOrCreateGuestConversationAsync(dto);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        return Ok(result);
    }

    /// <summary>Guest sends a message in a conversation. No auth.</summary>
    [HttpPost("conversations/{conversationId}/messages")]
    public async Task<ActionResult<ApiResponse<MessageDto>>> SendMessage(string conversationId, [FromBody] GuestSendMessageDto dto)
    {
        var result = await _messageService.SendGuestMessageAsync(conversationId, dto);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        return Ok(result);
    }

    /// <summary>Guest gets messages in a conversation (e.g. to load chat). No auth.</summary>
    [HttpGet("conversations/{conversationId}/messages")]
    public async Task<ActionResult<ApiResponse<List<MessageDto>>>> GetMessages(string conversationId, [FromQuery] string guestEmail, [FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        if (string.IsNullOrWhiteSpace(guestEmail))
            return BadRequest(ApiResponse<List<MessageDto>>.ErrorResult("guestEmail is required.", ResponseCodes.VALIDATION_ERROR));
        var result = await _messageService.GetGuestMessagesAsync(conversationId, guestEmail.Trim(), page, pageSize);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        return Ok(result);
    }

    /// <summary>Guest creates an order/inquiry (invoice request). Seller can then edit amount and negotiate. No auth.</summary>
    [HttpPost("orders")]
    public async Task<ActionResult<ApiResponse<OrderResponseDto>>> CreateOrder([FromBody] CreateGuestOrderDto dto)
    {
        var result = await _orderService.CreateGuestOrderAsync(dto);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        return CreatedAtAction(nameof(CreateOrder), new { id = result.Data!.Id }, result);
    }
}
