namespace Application.DTOs.Common;

/// <summary>Paged list with totals and optional empty-state copy for the UI.</summary>
public class PagedListDto<T>
{
    public IReadOnlyList<T> Items { get; set; } = Array.Empty<T>();
    public int Page { get; set; }
    public int PageSize { get; set; }
    public int TotalCount { get; set; }
    public int TotalPages => PageSize <= 0 ? 0 : (int)Math.Ceiling(TotalCount / (double)PageSize);
    public bool HasNextPage => Page < TotalPages;
    public bool HasPreviousPage => Page > 1 && TotalPages > 0;

    /// <summary>When Items is empty, a user-friendly explanation (e.g. "No orders yet").</summary>
    public string? EmptyStateMessage { get; set; }
}
