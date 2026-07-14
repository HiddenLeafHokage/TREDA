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
