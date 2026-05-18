namespace Application.DTOs.Vendor;

public class VendorDashboardStatsDto
{
    public int TotalProducts { get; set; }
    public int ActiveProducts { get; set; }
    public decimal TotalSales { get; set; }       // Sum of completed/shipped order amounts (N)
    public int OrdersToday { get; set; }
    public int PendingOrders { get; set; }
    public decimal WalletBalance { get; set; }    // Vendor's Treda wallet (for ads)

    /// <summary>Shown when there is no shipped/completed revenue yet.</summary>
    public string? SalesInsight { get; set; }
}
