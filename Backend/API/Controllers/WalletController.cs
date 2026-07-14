using API.Attributes;
using Application.Constants;
using Application.DTOs.Common;
using Application.DTOs.Wallet;
using Application.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace API.Controllers;

[ApiController]
[Route("api/vendor/wallet")]
[SimpleAuthorize(AppConstants.Roles.Vendor, AppConstants.Roles.Admin)]
public class WalletController : ControllerBase
{
    private readonly IWalletService _walletService;
    private readonly ILogger<WalletController> _logger;

    public WalletController(IWalletService walletService, ILogger<WalletController> logger)
    {
        _walletService = walletService;
        _logger = logger;
    }

    private string? VendorId => User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    [HttpGet("balance")]
    public async Task<ActionResult<ApiResponse<WalletBalanceDto>>> GetBalance()
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<WalletBalanceDto>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _walletService.GetBalanceAsync(VendorId);
        return Ok(result);
    }

    [HttpGet("transactions")]
    public async Task<ActionResult<ApiResponse<List<WalletTransactionDto>>>> GetTransactions([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        if (string.IsNullOrEmpty(VendorId))
            return Unauthorized(ApiResponse<List<WalletTransactionDto>>.ErrorResult("Unauthorized", ResponseCodes.UNAUTHORIZED));
        var result = await _walletService.GetTransactionsAsync(VendorId, page, pageSize);
        return Ok(result);
    }

}
