using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Wallet;

namespace Application.Interfaces;

public interface IWalletService
{
    Task<ApiResponse<WalletBalanceDto>> GetBalanceAsync(string vendorId);
    Task<ApiResponse<List<WalletTransactionDto>>> GetTransactionsAsync(string vendorId, int page = 1, int pageSize = AppConstants.DefaultPageSize);
    Task<ApiResponse<WalletBalanceDto>> PromoteProductAsync(string vendorId, string productId, PromoteProductDto dto);
}
