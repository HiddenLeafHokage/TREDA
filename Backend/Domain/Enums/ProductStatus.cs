namespace Domain.Enums;

/// <summary>Draft products are never shown on any public/buyer-facing endpoint until published.</summary>
public enum ProductStatus
{
    Draft = 0,
    Published = 1
}
