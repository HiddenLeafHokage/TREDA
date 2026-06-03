using System.Text.Json;
using System.Text.Json.Serialization;
using Domain.Enums;

namespace API.Json;

public sealed class ProductConditionJsonConverter : JsonConverter<ProductCondition>
{
    public override ProductCondition Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Number && reader.TryGetInt32(out var numericValue))
        {
            if (Enum.IsDefined(typeof(ProductCondition), numericValue))
                return (ProductCondition)numericValue;
        }

        if (reader.TokenType == JsonTokenType.String)
        {
            var value = reader.GetString()?.Trim();
            if (string.IsNullOrWhiteSpace(value))
                return ProductCondition.New;

            if (int.TryParse(value, out var numericStringValue) && Enum.IsDefined(typeof(ProductCondition), numericStringValue))
                return (ProductCondition)numericStringValue;

            var normalized = value.Replace("-", " ", StringComparison.Ordinal).Replace("_", " ", StringComparison.Ordinal).ToLowerInvariant();
            return normalized switch
            {
                "new" or "brand new" => ProductCondition.New,
                "used" => ProductCondition.Used,
                "refurbished" or "refurb" => ProductCondition.Refurbished,
                _ when Enum.TryParse<ProductCondition>(value, ignoreCase: true, out var parsed) => parsed,
                _ => throw new JsonException($"Invalid product condition '{value}'. Valid values are New, Used, or Refurbished.")
            };
        }

        throw new JsonException("Product condition must be a string or number.");
    }

    public override void Write(Utf8JsonWriter writer, ProductCondition value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString());
    }
}
