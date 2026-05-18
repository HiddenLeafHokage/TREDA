using API.Attributes;
using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Order;
using Application.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
[SimpleAuthorize(AppConstants.Roles.Vendor, AppConstants.Roles.Admin)]
public class OrdersController : ControllerBase
{
    private readonly IOrderService _orderService;
    private readonly ILogger<OrdersController> _logger;

    public OrdersController(IOrderService orderService, ILogger<OrdersController> logger)
    {
        _orderService = orderService;
        _logger = logger;
    }

    private string? VendorId => User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    [HttpGet]
    public async Task<ActionResult<ApiResponse<PagedListDto<OrderResponseDto>>>> GetOrders(
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] string? search,
        [FromQuery] string? status,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<PagedListDto<OrderResponseDto>>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _orderService.GetVendorOrdersPagedAsync(VendorId, search, status, from, to, page, pageSize);
        return Ok(result);
    }

    /// <summary>All orders in a date range (no pagination). For large histories use GET /api/orders with page/pageSize.</summary>
    [HttpGet("by-date-range")]
    public async Task<ActionResult<ApiResponse<List<OrderResponseDto>>>> GetOrdersByDateRange(
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<List<OrderResponseDto>>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _orderService.GetVendorOrdersAsync(VendorId, from, to);
        return Ok(result);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<ApiResponse<OrderResponseDto>>> GetById(string id)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<OrderResponseDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _orderService.GetByIdAsync(id, VendorId);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        return Ok(result);
    }

    [HttpPost]
    public async Task<ActionResult<ApiResponse<OrderResponseDto>>> Create([FromBody] CreateOrderDto dto)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<OrderResponseDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _orderService.CreateAsync(VendorId, dto);
        return CreatedAtAction(nameof(GetById), new { id = result.Data!.Id }, result);
    }

    [HttpPut("{id}/status")]
    public async Task<ActionResult<ApiResponse<OrderResponseDto>>> UpdateStatus(string id, [FromBody] UpdateOrderStatusDto dto)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<OrderResponseDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _orderService.UpdateStatusAsync(id, VendorId, dto);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        return Ok(result);
    }

    /// <summary>Update order (e.g. negotiate invoice amount, or status).</summary>
    [HttpPut("{id}")]
    public async Task<ActionResult<ApiResponse<OrderResponseDto>>> UpdateOrder(string id, [FromBody] UpdateOrderDto dto)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<OrderResponseDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _orderService.UpdateOrderAsync(id, VendorId, dto);
        if (result.Code == ResponseCodes.NOT_FOUND) return NotFound(result);
        return Ok(result);
    }
}
