using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Wallet;
using Application.Interfaces;
using Domain.Entities;
using Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Persistence.Data;

namespace Application.Services;

public class WalletService : IWalletService
{
    private readonly TredaDbContext _context;
    private readonly ILogger<WalletService> _logger;

    public WalletService(TredaDbContext context, ILogger<WalletService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<ApiResponse<WalletBalanceDto>> GetBalanceAsync(string vendorId)
    {
        var wallet = await GetOrCreateWalletAsync(vendorId);
        return ApiResponse<WalletBalanceDto>.SuccessResult(new WalletBalanceDto
        {
            Balance = wallet.Balance,
            VendorId = wallet.VendorId
        });
    }

    public async Task<ApiResponse<List<WalletTransactionDto>>> GetTransactionsAsync(string vendorId, int page = 1, int pageSize = AppConstants.DefaultPageSize)
    {
        var list = await _context.WalletTransactions
            .Where(t => t.VendorId == vendorId)
            .OrderByDescending(t => t.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
        var dtos = list.Select(t => new WalletTransactionDto
        {
            Id = t.Id,
            Amount = t.Amount,
            Type = t.Type.ToString(),
            Description = t.Description,
            Reference = t.Reference,
            CreatedAt = t.CreatedAt
        }).ToList();
        return ApiResponse<List<WalletTransactionDto>>.SuccessResult(dtos);
    }

    public async Task<ApiResponse<WalletBalanceDto>> PromoteProductAsync(string vendorId, string productId, PromoteProductDto dto)
    {
        var product = await _context.Products.FirstOrDefaultAsync(p => p.Id == productId && p.VendorId == vendorId);
        if (product == null)
            return ApiResponse<WalletBalanceDto>.ErrorResult("Product not found.", ResponseCodes.NOT_FOUND);

        var wallet = await GetOrCreateWalletAsync(vendorId);
        var amount = dto.Amount;
        if (wallet.Balance < amount)
            return ApiResponse<WalletBalanceDto>.ErrorResult("Insufficient wallet balance.", ResponseCodes.VALIDATION_ERROR);

        wallet.Balance -= amount;
        wallet.UpdatedAt = DateTime.UtcNow;

        var start = DateTime.UtcNow;
        var end = start.AddDays(dto.DurationDays);
        _context.WalletTransactions.Add(new WalletTransaction
        {
            Id = Guid.NewGuid().ToString(),
            VendorId = vendorId,
            Amount = -amount,
            Type = WalletTransactionType.Debit,
            Description = "Treda Ads - Promote listing",
            Reference = productId,
            CreatedAt = DateTime.UtcNow
        });

        _context.ProductPromotions.Add(new ProductPromotion
        {
            Id = Guid.NewGuid().ToString(),
            ProductId = productId,
            VendorId = vendorId,
            AmountPaid = amount,
            StartDate = start,
            EndDate = end,
            CreatedAt = DateTime.UtcNow
        });

        await _context.SaveChangesAsync();
        return ApiResponse<WalletBalanceDto>.SuccessResult(new WalletBalanceDto { Balance = wallet.Balance, VendorId = vendorId }, "Listing promoted.");
    }

    private async Task<VendorWallet> GetOrCreateWalletAsync(string vendorId)
    {
        var wallet = await _context.VendorWallets.FirstOrDefaultAsync(w => w.VendorId == vendorId);
        if (wallet != null) return wallet;
        wallet = new VendorWallet
        {
            Id = Guid.NewGuid().ToString(),
            VendorId = vendorId,
            Balance = 0,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        _context.VendorWallets.Add(wallet);
        await _context.SaveChangesAsync();
        return wallet;
    }
}
