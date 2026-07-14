namespace Application.DTOs.Product;

/// <summary>Promote (feature) a product or remove it from promotions. Paid plans only, capped per plan.</summary>
public class PromoteRequestDto
{
    public bool Promoted { get; set; } = true;
}
