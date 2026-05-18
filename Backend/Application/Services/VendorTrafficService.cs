using Application.Interfaces;
using Domain.Entities;
using Domain.Enums;
using Microsoft.Extensions.Logging;
using Persistence.Data;

namespace Application.Services;

public class VendorTrafficService : IVendorTrafficService
{
    private readonly TredaDbContext _context;
    private readonly ILogger<VendorTrafficService> _logger;

    public VendorTrafficService(TredaDbContext context, ILogger<VendorTrafficService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task RecordProductViewAsync(string vendorId, string? productId)
    {
        try
        {
            _context.VendorTrafficEvents.Add(new VendorTrafficEvent
            {
                VendorId = vendorId,
                EventType = VendorTrafficEventType.ProductView,
                ProductId = productId,
                CreatedAt = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Traffic: could not record product view for vendor {VendorId}", vendorId);
        }
    }

    public async Task RecordEngagementAsync(string vendorId, string? productId, VendorTrafficEventType type)
    {
        try
        {
            _context.VendorTrafficEvents.Add(new VendorTrafficEvent
            {
                VendorId = vendorId,
                EventType = type,
                ProductId = productId,
                CreatedAt = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Traffic: could not record {Type} for vendor {VendorId}", type, vendorId);
        }
    }

    public async Task RecordSearchExposureAsync(IReadOnlyCollection<string> vendorIds, string searchTerm)
    {
        if (vendorIds.Count == 0 || string.IsNullOrWhiteSpace(searchTerm)) return;
        var term = searchTerm.Trim();
        if (term.Length > 500) term = term[..500];
        try
        {
            foreach (var vid in vendorIds.Distinct(StringComparer.Ordinal))
            {
                _context.VendorTrafficEvents.Add(new VendorTrafficEvent
                {
                    VendorId = vid,
                    EventType = VendorTrafficEventType.Search,
                    SearchTerm = term,
                    CreatedAt = DateTime.UtcNow
                });
            }
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Traffic: could not record search exposure");
        }
    }
}
