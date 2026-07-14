using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Message;
using Application.DTOs.Order;
using Application.DTOs.Product;
using Application.DTOs.Vendor;
using Application.Interfaces;
using Microsoft.EntityFrameworkCore;
using Persistence.Data;

namespace Application.Services;

public class VendorSearchService : IVendorSearchService
{
    private readonly TredaDbContext _context;

    public VendorSearchService(TredaDbContext context)
    {
        _context = context;
    }

    public async Task<ApiResponse<VendorSearchResultDto>> SearchAsync(string vendorId, string query, int perSectionLimit = 5)
    {
        perSectionLimit = Math.Clamp(perSectionLimit, 1, 50);
        var q = (query ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(q))
        {
            return ApiResponse<VendorSearchResultDto>.ErrorResult("Query is required.", ResponseCodes.VALIDATION_ERROR);
        }

        var products = await _context.Products
            .Include(p => p.Category)
            .Where(p => p.VendorId == vendorId && (p.Name.Contains(q) || (p.Description != null && p.Description.Contains(q))))
            .OrderByDescending(p => p.UpdatedAt)
            .Take(perSectionLimit)
            .ToListAsync();

        var orders = await _context.Orders
            .Include(o => o.Items)
            .Where(o => o.VendorId == vendorId &&
                        (o.CustomerName.Contains(q) ||
                         (o.GuestPhone != null && o.GuestPhone.Contains(q)) ||
                         (o.GuestEmail != null && o.GuestEmail.Contains(q)) ||
                         o.Items.Any(i => i.ProductName.Contains(q))))
            .OrderByDescending(o => o.CreatedAt)
            .Take(perSectionLimit)
            .ToListAsync();

        var conversations = await _context.Conversations
            .Include(c => c.Buyer)
            .Include(c => c.Product)
            .Include(c => c.Messages)
            .Where(c => c.VendorId == vendorId &&
                        ((c.Buyer != null && c.Buyer.FullName.Contains(q)) ||
                         (c.GuestName != null && c.GuestName.Contains(q)) ||
                         (c.GuestEmail != null && c.GuestEmail.Contains(q)) ||
                         (c.Product != null && c.Product.Name.Contains(q))))
            .OrderByDescending(c => c.UpdatedAt)
            .Take(perSectionLimit)
            .ToListAsync();

        static ProductResponseDto MapProduct(Domain.Entities.Product p) => new()
        {
            Id = p.Id,
            Name = p.Name,
            Description = p.Description ?? "",
            Price = p.Price,
            CategoryId = p.CategoryId,
            CategoryName = p.Category?.Name ?? "",
            Condition = p.Condition.ToString(),
            Location = p.Location,
            ImageUrls = p.ImageUrls ?? new List<string>(),
            StockQuantity = p.StockQuantity,
            IsActive = p.IsActive,
            VendorId = p.VendorId,
            CreatedAt = p.CreatedAt,
            UpdatedAt = p.UpdatedAt
        };

        static OrderResponseDto MapOrder(Domain.Entities.Order o) => new()
        {
            Id = o.Id,
            OrderNumber = o.OrderNumber,
            OrderIdDisplay = $"#{o.OrderNumber}",
            InvoiceNumber = $"INV-{o.CreatedAt:yyyy}-{o.OrderNumber}",
            CustomerName = o.CustomerName,
            GuestEmail = o.GuestEmail,
            GuestName = o.GuestName,
            GuestPhone = o.GuestPhone,
            Items = o.Items.Select(i => new OrderItemDto
            {
                ProductId = i.ProductId,
                ProductName = i.ProductName,
                UnitPrice = i.UnitPrice,
                Quantity = i.Quantity,
                LineTotal = i.LineTotal
            }).ToList(),
            Subtotal = o.Subtotal,
            DeliveryFee = o.DeliveryFee,
            Total = o.Total,
            Status = o.Status.ToString(),
            PaymentStatus = o.PaymentStatus.ToString(),
            CreatedAt = o.CreatedAt,
            UpdatedAt = o.UpdatedAt
        };

        var convDtos = conversations.Select(c =>
        {
            var last = c.Messages.OrderByDescending(m => m.SentAt).FirstOrDefault();
            return new ConversationDto
            {
                Id = c.Id,
                BuyerId = c.BuyerId,
                BuyerName = c.Buyer?.FullName ?? c.GuestName ?? AppConstants.DefaultBuyerDisplayName,
                GuestEmail = c.GuestEmail,
                ProductId = c.ProductId,
                ProductName = c.Product?.Name,
                LastMessagePreview = last?.Content,
                LastMessageAt = last?.SentAt,
                UnreadCount = 0
            };
        }).ToList();

        var any = products.Count > 0 || orders.Count > 0 || convDtos.Count > 0;
        var result = new VendorSearchResultDto
        {
            Products = new PagedListDto<ProductResponseDto>
            {
                Items = products.Select(MapProduct).ToList(),
                Page = 1,
                PageSize = perSectionLimit,
                TotalCount = products.Count,
                EmptyStateMessage = products.Count == 0 ? "No matching products." : null
            },
            Orders = new PagedListDto<OrderResponseDto>
            {
                Items = orders.Select(MapOrder).ToList(),
                Page = 1,
                PageSize = perSectionLimit,
                TotalCount = orders.Count,
                EmptyStateMessage = orders.Count == 0 ? "No matching orders." : null
            },
            Conversations = new PagedListDto<ConversationDto>
            {
                Items = convDtos,
                Page = 1,
                PageSize = perSectionLimit,
                TotalCount = convDtos.Count,
                EmptyStateMessage = convDtos.Count == 0 ? "No matching conversations." : null
            },
            GlobalEmptyMessage = any ? null : AppConstants.EmptyStateMessages.VendorSearchNoMatches
        };

        var msg = any ? "Search completed." : AppConstants.EmptyStateMessages.VendorSearchNoMatches;
        return ApiResponse<VendorSearchResultDto>.SuccessResult(result, msg);
    }
}
