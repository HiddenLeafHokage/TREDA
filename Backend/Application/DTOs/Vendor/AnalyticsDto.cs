namespace Application.DTOs.Vendor;

public class AnalyticsDto
{
    public List<SalesByDayDto> Performance { get; set; } = new();
    public int Favourites { get; set; }
    public int ClickThrough { get; set; }
    public int Views { get; set; }
    public int TotalSearches { get; set; }

    /// <summary>When there are no shipped/completed orders in the period.</summary>
    public string? SalesInsight { get; set; }

    /// <summary>When engagement metrics are all zero for the period.</summary>
    public string? EngagementInsight { get; set; }
}

public class SalesByDayDto
{
    public DateTime Date { get; set; }
    public decimal TotalSales { get; set; }
    public int OrderCount { get; set; }
}
