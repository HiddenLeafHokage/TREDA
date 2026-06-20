using System.Text.RegularExpressions;

namespace Application.Helpers;

public static partial class VendorSlugHelper
{
    public static string CreateSlug(string? value)
    {
        var source = string.IsNullOrWhiteSpace(value) ? "shop" : value.Trim().ToLowerInvariant();
        source = NonAlphaNumericRegex().Replace(source, "-");
        source = MultiDashRegex().Replace(source, "-").Trim('-');
        return string.IsNullOrWhiteSpace(source) ? "shop" : source;
    }

    [GeneratedRegex(@"[^a-z0-9]+")]
    private static partial Regex NonAlphaNumericRegex();

    [GeneratedRegex(@"-+")]
    private static partial Regex MultiDashRegex();
}
