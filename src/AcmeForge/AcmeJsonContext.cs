using System.Text.Json.Serialization;
using AcmeForge.Resources;

namespace AcmeForge;

/// <summary>
/// ACME 资源 JSON 源生成上下文。AOT 安全，无反射。
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(AcmeDirectory))]
[JsonSerializable(typeof(AcmeAccount))]
[JsonSerializable(typeof(AcmeOrder))]
[JsonSerializable(typeof(AcmeAuthorization))]
[JsonSerializable(typeof(AcmeChallenge))]
[JsonSerializable(typeof(AcmeProblem))]
internal sealed partial class AcmeJsonContext : JsonSerializerContext
{
    public static AcmeJsonContext Instance { get; } = new();
}
