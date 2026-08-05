using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AcmeForge.Dns;

/// <summary>
/// 兼容 JSON 字符串与数字的反序列化器，且序列化时把数字字符串写为 JSON 数字。
/// 用于腾讯云 DNS 请求体中的 DomainId/RecordId（API 文档类型为 Integer，示例为 62/162）。
/// AOT 安全：仅使用 Utf8JsonReader/Writer，无反射。
/// </summary>
public sealed class JsonStringAsNumberConverter : JsonConverter<string>
{
    public override string Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.String:
                return reader.GetString() ?? string.Empty;
            case JsonTokenType.Number:
                return reader.GetDecimal().ToString(CultureInfo.InvariantCulture);
            case JsonTokenType.Null:
                return string.Empty;
            default:
                throw new JsonException($"无法将 {reader.TokenType} 转换为字符串");
        }
    }

    public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
    {
        if (ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number))
        {
            writer.WriteNumberValue(number);
        }
        else
        {
            writer.WriteStringValue(value);
        }
    }
}
