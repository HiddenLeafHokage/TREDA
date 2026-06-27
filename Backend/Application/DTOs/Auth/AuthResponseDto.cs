using Application.DTOs.Category;

namespace Application.DTOs.Auth;
public class AuthResponseDto
{
    public string Id { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string UserType { get; set; } = string.Empty;
    public bool EmailVerified { get; set; }
    public string? BusinessName { get; set; }

    /// <summary>Shop logo URL, or null if none was uploaded (frontend then shows <see cref="DisplayInitial"/>).</summary>
    public string? BusinessLogoUrl { get; set; }

    /// <summary>First letter of the business name (fallback avatar when there is no logo), e.g. "D".</summary>
    public string DisplayInitial { get; set; } = string.Empty;

    /// <summary>The categories this vendor selected, so the UI can show them right after login.</summary>
    public List<CategoryDto> BusinessCategories { get; set; } = new();

    public bool ProfileCompleted { get; set; }
    public string Token { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public DateTime Expiration { get; set; }
}
