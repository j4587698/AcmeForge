using System.Text.Json.Serialization;

namespace AcmeForge.Dns;

/// <summary>
/// DNS 提供商 API 响应/请求 JSON 源生成上下文。AOT 安全，无反射。
/// </summary>
[JsonSourceGenerationOptions(
    GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(CloudflareDnsResponse))]
[JsonSerializable(typeof(CloudflareDnsRecordsResponse))]
[JsonSerializable(typeof(CloudflareZonesResponse))]
[JsonSerializable(typeof(CloudflareTokenVerifyResponse))]
[JsonSerializable(typeof(CloudflareDnsRecord))]
[JsonSerializable(typeof(CloudflareZone))]
[JsonSerializable(typeof(CloudflareTokenInfo))]
[JsonSerializable(typeof(CloudflareErrorInfo))]
[JsonSerializable(typeof(CloudflareDnsRecordRequest))]
[JsonSerializable(typeof(AliyunDnsResponse))]
[JsonSerializable(typeof(AliyunDomainsResponse))]
[JsonSerializable(typeof(AliyunRecordsResponse))]
[JsonSerializable(typeof(AliyunDomain))]
[JsonSerializable(typeof(AliyunDnsRecord))]
[JsonSerializable(typeof(AzureTokenResponse))]
[JsonSerializable(typeof(AzureDnsZonesResponse))]
[JsonSerializable(typeof(AzureDnsZone))]
[JsonSerializable(typeof(AzureDnsRecordSetRequest))]
[JsonSerializable(typeof(AzureDnsRecordSetProperties))]
[JsonSerializable(typeof(AzureTxtRecordValue))]
[JsonSerializable(typeof(DnsPodApiResponse))]
[JsonSerializable(typeof(DnsPodDomain))]
[JsonSerializable(typeof(DnsPodRecord))]
[JsonSerializable(typeof(DnsPodTraditionalStatus))]
[JsonSerializable(typeof(DnsPodTraditionalDomain))]
[JsonSerializable(typeof(DnsPodTraditionalRecord))]
[JsonSerializable(typeof(DnsPodTraditionalListDomainsResponse))]
[JsonSerializable(typeof(DnsPodTraditionalListRecordsResponse))]
[JsonSerializable(typeof(DnsPodTraditionalCreateRecordResponse))]
[JsonSerializable(typeof(DnsPodTraditionalDeleteResponse))]
[JsonSerializable(typeof(List<GoDaddyDnsRecord>))]
[JsonSerializable(typeof(List<GoDaddyDomain>))]
[JsonSerializable(typeof(TencentDnsResponse))]
[JsonSerializable(typeof(TencentResponse))]
[JsonSerializable(typeof(TencentDomainsResponse))]
[JsonSerializable(typeof(TencentDomainsResponseData))]
[JsonSerializable(typeof(TencentRecordsResponse))]
[JsonSerializable(typeof(TencentRecordsResponseData))]
[JsonSerializable(typeof(TencentDomain))]
[JsonSerializable(typeof(TencentDnsRecord))]
[JsonSerializable(typeof(TencentError))]
[JsonSerializable(typeof(TencentCreateRecordRequest))]
[JsonSerializable(typeof(TencentDeleteRecordRequest))]
[JsonSerializable(typeof(TencentModifyRecordRequest))]
[JsonSerializable(typeof(TencentDescribeRecordListRequest))]
internal sealed partial class DnsJsonContext : JsonSerializerContext
{
    public static DnsJsonContext Instance { get; } = new();
}
