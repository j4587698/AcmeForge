using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AcmeForge.Dns;

/// <summary>
/// AWS Route 53 DNS API 提供商实现
/// </summary>
public class AwsRoute53DnsProvider : IDnsProvider
{
    private readonly ILogger<AwsRoute53DnsProvider> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;

    public AwsRoute53DnsProvider(
        ILogger<AwsRoute53DnsProvider> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _httpClient = _httpClientFactory.CreateClient("AwsRoute53");
    }

    public string Name => "aws";
    public string DisplayName => "AWS Route 53";
    public bool RequiresCredentials => true;

    /// <summary>
    /// 创建 DNS TXT 记录
    /// </summary>
    public async Task<DnsOperationResult> CreateTxtRecordAsync(string domain, string recordName, string recordValue, IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            _logger.LogInformation("创建 AWS Route 53 DNS TXT 记录: {RecordName} = {RecordValue}", recordName, recordValue);

            var accessKeyId = GetAccessKeyId(credentials);
            var secretAccessKey = GetSecretAccessKey(credentials);
            var region = GetRegion(credentials);

            if (string.IsNullOrEmpty(accessKeyId) || string.IsNullOrEmpty(secretAccessKey))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = "AWS Access Key ID 或 Secret Access Key 未提供",
                    ErrorCode = "MISSING_CREDENTIALS"
                };
            }

            // 获取 Hosted Zone ID
            var hostedZoneId = await GetHostedZoneId(domain, accessKeyId, secretAccessKey, region);
            if (string.IsNullOrEmpty(hostedZoneId))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"无法获取域名 {domain} 的 Hosted Zone ID",
                    ErrorCode = "ZONE_NOT_FOUND"
                };
            }

            // 构建完整的记录名称（需要以点结尾）
            var fullRecordName = recordName;
            if (!fullRecordName.EndsWith("."))
            {
                fullRecordName += ".";
            }

            // 创建变更请求 XML
            var changeXml = $@"<?xml version=""1.0"" encoding=""UTF-8""?>
<ChangeResourceRecordSetsRequest xmlns=""https://route53.amazonaws.com/doc/2013-04-01/"">
    <ChangeBatch>
        <Changes>
            <Change>
                <Action>UPSERT</Action>
                <ResourceRecordSet>
                    <Name>{fullRecordName}</Name>
                    <Type>TXT</Type>
                    <TTL>120</TTL>
                    <ResourceRecords>
                        <ResourceRecord>
                            <Value>""{recordValue}""</Value>
                        </ResourceRecord>
                    </ResourceRecords>
                </ResourceRecordSet>
            </Change>
        </Changes>
    </ChangeBatch>
</ChangeResourceRecordSetsRequest>";

            // 发送请求
            var endpoint = $"https://route53.amazonaws.com/2013-04-01/hostedzone/{hostedZoneId}/rrset";
            var response = await SendAwsRequestAsync("POST", endpoint, changeXml, accessKeyId, secretAccessKey, region);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("创建 AWS Route 53 DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"创建 DNS 记录失败: {response.StatusCode}",
                    ErrorCode = "CREATE_FAILED",
                    Details = responseContent
                };
            }

            _logger.LogInformation("AWS Route 53 DNS TXT 记录创建成功: {RecordName}", recordName);
            return new DnsOperationResult
            {
                Success = true,
                Message = "DNS 记录创建成功",
                Details = $"Hosted Zone: {hostedZoneId}"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建 AWS Route 53 DNS 记录异常: {RecordName}", recordName);
            return new DnsOperationResult
            {
                Success = false,
                Message = $"创建 DNS 记录异常: {ex.Message}",
                ErrorCode = "EXCEPTION",
                Details = ex.ToString()
            };
        }
    }

    /// <summary>
    /// 删除 DNS TXT 记录
    /// </summary>
    public async Task<DnsOperationResult> DeleteTxtRecordAsync(string domain, string recordName, string recordValue, IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            _logger.LogInformation("删除 AWS Route 53 DNS TXT 记录: {RecordName}", recordName);

            var accessKeyId = GetAccessKeyId(credentials);
            var secretAccessKey = GetSecretAccessKey(credentials);
            var region = GetRegion(credentials);

            if (string.IsNullOrEmpty(accessKeyId) || string.IsNullOrEmpty(secretAccessKey))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = "AWS Access Key ID 或 Secret Access Key 未提供",
                    ErrorCode = "MISSING_CREDENTIALS"
                };
            }

            // 获取 Hosted Zone ID
            var hostedZoneId = await GetHostedZoneId(domain, accessKeyId, secretAccessKey, region);
            if (string.IsNullOrEmpty(hostedZoneId))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"无法获取域名 {domain} 的 Hosted Zone ID",
                    ErrorCode = "ZONE_NOT_FOUND"
                };
            }

            // 构建完整的记录名称
            var fullRecordName = recordName;
            if (!fullRecordName.EndsWith("."))
            {
                fullRecordName += ".";
            }

            // 创建删除请求 XML
            var changeXml = $@"<?xml version=""1.0"" encoding=""UTF-8""?>
<ChangeResourceRecordSetsRequest xmlns=""https://route53.amazonaws.com/doc/2013-04-01/"">
    <ChangeBatch>
        <Changes>
            <Change>
                <Action>DELETE</Action>
                <ResourceRecordSet>
                    <Name>{fullRecordName}</Name>
                    <Type>TXT</Type>
                    <TTL>120</TTL>
                    <ResourceRecords>
                        <ResourceRecord>
                            <Value>""{recordValue}""</Value>
                        </ResourceRecord>
                    </ResourceRecords>
                </ResourceRecordSet>
            </Change>
        </Changes>
    </ChangeBatch>
</ChangeResourceRecordSetsRequest>";

            // 发送请求
            var endpoint = $"https://route53.amazonaws.com/2013-04-01/hostedzone/{hostedZoneId}/rrset";
            var response = await SendAwsRequestAsync("POST", endpoint, changeXml, accessKeyId, secretAccessKey, region);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("删除 AWS Route 53 DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"删除 DNS 记录失败: {response.StatusCode}",
                    ErrorCode = "DELETE_FAILED",
                    Details = responseContent
                };
            }

            _logger.LogInformation("AWS Route 53 DNS TXT 记录删除成功: {RecordName}", recordName);
            return new DnsOperationResult
            {
                Success = true,
                Message = "DNS 记录删除成功"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除 AWS Route 53 DNS 记录异常: {RecordName}", recordName);
            return new DnsOperationResult
            {
                Success = false,
                Message = $"删除 DNS 记录异常: {ex.Message}",
                ErrorCode = "EXCEPTION",
                Details = ex.ToString()
            };
        }
    }

    /// <summary>
    /// 测试连接
    /// </summary>
    public async Task<DnsTestResult> TestConnectionAsync(IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            _logger.LogInformation("测试 AWS Route 53 DNS 连接");

            var accessKeyId = GetAccessKeyId(credentials);
            var secretAccessKey = GetSecretAccessKey(credentials);
            var region = GetRegion(credentials);

            if (string.IsNullOrEmpty(accessKeyId) || string.IsNullOrEmpty(secretAccessKey))
            {
                return new DnsTestResult
                {
                    Success = false,
                    Message = "AWS Access Key ID 或 Secret Access Key 未提供",
                    ErrorCode = "MISSING_CREDENTIALS"
                };
            }

            // 测试列出 Hosted Zones
            var endpoint = $"https://route53.amazonaws.com/2013-04-01/hostedzone";
            var response = await SendAwsRequestAsync("GET", endpoint, null, accessKeyId, secretAccessKey, region);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("AWS Route 53 API 认证失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsTestResult
                {
                    Success = false,
                    Message = $"API 认证失败: {response.StatusCode}",
                    ErrorCode = "AUTH_FAILED",
                    Details = responseContent
                };
            }

            // 解析响应
            var zones = ParseHostedZones(responseContent);

            return new DnsTestResult
            {
                Success = true,
                Message = "AWS Route 53 API 连接测试成功",
                Details = $"找到 {zones.Count} 个 Hosted Zone"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "测试 AWS Route 53 DNS 连接异常");
            return new DnsTestResult
            {
                Success = false,
                Message = $"连接测试异常: {ex.Message}",
                ErrorCode = "EXCEPTION",
                Details = ex.ToString()
            };
        }
    }

    /// <summary>
    /// 删除所有匹配名称的 DNS TXT 记录
    /// </summary>
    public async Task<DnsOperationResult> DeleteAllTxtRecordsByNameAsync(string domain, string recordName, IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            _logger.LogInformation("AWS Route 53: 删除所有匹配的 DNS TXT 记录: {RecordName}", recordName);

            var accessKeyId = GetAccessKeyId(credentials);
            var secretAccessKey = GetSecretAccessKey(credentials);
            var region = GetRegion(credentials);

            if (string.IsNullOrEmpty(accessKeyId) || string.IsNullOrEmpty(secretAccessKey))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = "缺少 AWS 凭据",
                    ErrorCode = "MISSING_CREDENTIALS"
                };
            }

            // 获取 Hosted Zone ID
            var hostedZoneId = await GetHostedZoneId(domain, accessKeyId, secretAccessKey, region);
            if (string.IsNullOrEmpty(hostedZoneId))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"无法获取域名 {domain} 的 Hosted Zone ID",
                    ErrorCode = "ZONE_NOT_FOUND"
                };
            }

            // 列出所有记录
            var records = await ListTxtRecords(hostedZoneId, recordName, accessKeyId, secretAccessKey, region);
            if (records == null || records.Count == 0)
            {
                return new DnsOperationResult
                {
                    Success = true,
                    Message = "没有找到匹配的记录"
                };
            }

            // 批量删除记录
            var deletedCount = 0;
            foreach (var record in records)
            {
                var deleteResult = await DeleteRecord(hostedZoneId, record, accessKeyId, secretAccessKey, region);
                if (deleteResult)
                {
                    deletedCount++;
                }
            }

            return new DnsOperationResult
            {
                Success = true,
                Message = $"成功删除 {deletedCount} 条 DNS TXT 记录",
                Details = $"已删除 {deletedCount} 条记录"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AWS Route 53 删除所有 DNS TXT 记录时发生错误: {RecordName}", recordName);
            return new DnsOperationResult
            {
                Success = false,
                Message = $"删除 DNS TXT 记录时发生错误: {ex.Message}",
                ErrorCode = "EXCEPTION"
            };
        }
    }

    #region 私有方法

    // Route 53 为全局服务：端点为 route53.amazonaws.com，签名 region 固定 us-east-1（北京/宁夏除外）。
    private const string Route53EndpointHost = "route53.amazonaws.com";
    private const string Route53SigningRegion = "us-east-1";

    private string? GetAccessKeyId(IReadOnlyDictionary<string, object?>? credentials)
    {
        return credentials?.GetValueOrDefault("accessKeyId")?.ToString()
               ?? credentials?.GetValueOrDefault("access_key_id")?.ToString()
               ?? _configuration["DnsProviders:Aws:AccessKeyId"];
    }

    private string? GetSecretAccessKey(IReadOnlyDictionary<string, object?>? credentials)
    {
        return credentials?.GetValueOrDefault("secretAccessKey")?.ToString()
               ?? credentials?.GetValueOrDefault("secret_access_key")?.ToString()
               ?? _configuration["DnsProviders:Aws:SecretAccessKey"];
    }

    private string GetRegion(IReadOnlyDictionary<string, object?>? credentials)
    {
        return credentials?.GetValueOrDefault("region")?.ToString()
               ?? _configuration["DnsProviders:Aws:Region"]
               ?? "us-east-1";
    }

    private async Task<string?> GetHostedZoneId(string domain, string accessKeyId, string secretAccessKey, string region)
    {
        try
        {
            var rootDomain = DnsDomainHelper.ExtractRootDomain(domain);
            var endpoint = $"https://route53.amazonaws.com/2013-04-01/hostedzone";
            var response = await SendAwsRequestAsync("GET", endpoint, null, accessKeyId, secretAccessKey, region);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("获取 Hosted Zone ID 失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return null;
            }

            // 解析 XML 响应
            var zones = ParseHostedZones(responseContent);
            var matchingZone = zones.FirstOrDefault(z =>
                z.Name.Equals(rootDomain, StringComparison.OrdinalIgnoreCase) ||
                z.Name.Equals(rootDomain + ".", StringComparison.OrdinalIgnoreCase));

            return matchingZone?.Id?.Replace("/hostedzone/", "");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取 Hosted Zone ID 异常: {Domain}", domain);
            return null;
        }
    }

    private async Task<HttpResponseMessage> SendAwsRequestAsync(string method, string endpoint, string? content, string accessKeyId, string secretAccessKey, string region)
    {
        // Route 53 全局服务签名 region 固定 us-east-1，与传入 region 无关。
        region = Route53SigningRegion;
        var uri = new Uri(endpoint);
        var now = DateTime.UtcNow;
        var dateStamp = now.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        var amzDate = now.ToString("yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture);

        // 创建 AWS Signature V4
        var canonicalRequest = await CreateCanonicalRequest(method, uri, content);
        var stringToSign = CreateStringToSign(amzDate, dateStamp, canonicalRequest, region);
        var signature = CalculateSignature(stringToSign, dateStamp, secretAccessKey, region);
        var authorizationHeader = CreateAuthorizationHeader(accessKeyId, dateStamp, region, signature);

        using var request = new HttpRequestMessage(new HttpMethod(method), uri);
        request.Headers.Add("Host", uri.Host);
        request.Headers.Add("X-Amz-Date", amzDate);
        request.Headers.Add("Authorization", authorizationHeader);

        if (!string.IsNullOrEmpty(content))
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/xml");
        }

        return await _httpClient.SendAsync(request);
    }

    private async Task<string> CreateCanonicalRequest(string method, Uri uri, string? body)
    {
        var canonicalUri = uri.AbsolutePath;
        var canonicalQueryString = uri.Query.TrimStart('?');
        var canonicalHeaders = $"host:{uri.Host}\nx-amz-content-sha256:{await GetHash(body ?? "")}\nx-amz-date:{DateTime.UtcNow:yyyyMMddTHHmmssZ}\n";
        var signedHeaders = "host;x-amz-content-sha256;x-amz-date";
        var payloadHash = await GetHash(body ?? "");

        return $"{method}\n{canonicalUri}\n{canonicalQueryString}\n{canonicalHeaders}\n{signedHeaders}\n{payloadHash}";
    }

    private string CreateStringToSign(string amzDate, string dateStamp, string canonicalRequest, string region)
    {
        var credentialScope = $"{dateStamp}/{region}/route53/aws4_request";
        var canonicalRequestHash = GetHashSync(canonicalRequest);

        return $"AWS4-HMAC-SHA256\n{amzDate}\n{credentialScope}\n{canonicalRequestHash}";
    }

    private string CalculateSignature(string stringToSign, string dateStamp, string secretAccessKey, string region)
    {
        var kSecret = Encoding.UTF8.GetBytes($"AWS4{secretAccessKey}");
        var kDate = HmacSha256(kSecret, dateStamp);
        var kRegion = HmacSha256(kDate, region);
        var kService = HmacSha256(kRegion, "route53");
        var kSigning = HmacSha256(kService, "aws4_request");
        var signature = HmacSha256(kSigning, stringToSign);

        return BitConverter.ToString(signature).Replace("-", "").ToLowerInvariant();
    }

    private string CreateAuthorizationHeader(string accessKeyId, string dateStamp, string region, string signature)
    {
        var credentialScope = $"{dateStamp}/{region}/route53/aws4_request";
        return $"AWS4-HMAC-SHA256 Credential={accessKeyId}/{credentialScope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}";
    }

    private async Task<string> GetHash(string content)
    {
        using var sha256 = SHA256.Create();
        var hash = await sha256.ComputeHashAsync(new MemoryStream(Encoding.UTF8.GetBytes(content)));
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    private string GetHashSync(string content)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(content));
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    private byte[] HmacSha256(byte[] key, string data)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
    }

    private List<AwsHostedZone> ParseHostedZones(string xmlContent)
    {
        var zones = new List<AwsHostedZone>();
        try
        {
            // 简单的 XML 解析
            var doc = System.Xml.Linq.XDocument.Parse(xmlContent);
            var ns = doc.Root?.GetDefaultNamespace() ?? System.Xml.Linq.XNamespace.None;
            foreach (var zone in doc.Descendants(ns + "HostedZone"))
            {
                zones.Add(new AwsHostedZone
                {
                    Id = zone.Element(ns + "Id")?.Value ?? "",
                    Name = zone.Element(ns + "Name")?.Value ?? ""
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "解析 AWS Hosted Zone XML 失败");
        }
        return zones;
    }

    private async Task<List<AwsDnsRecord>> ListTxtRecords(string hostedZoneId, string recordName, string accessKeyId, string secretAccessKey, string region)
    {
        var records = new List<AwsDnsRecord>();
        try
        {
            var endpoint = $"https://route53.amazonaws.com/2013-04-01/hostedzone/{hostedZoneId}/rrset?type=TXT&name={Uri.EscapeDataString(recordName)}";
            var response = await SendAwsRequestAsync("GET", endpoint, null, accessKeyId, secretAccessKey, region);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var doc = System.Xml.Linq.XDocument.Parse(responseContent);
                var ns = doc.Root?.GetDefaultNamespace() ?? System.Xml.Linq.XNamespace.None;
                foreach (var record in doc.Descendants(ns + "ResourceRecordSet"))
                {
                    var type = record.Element(ns + "Type")?.Value;
                    if (type == "TXT")
                    {
                        records.Add(new AwsDnsRecord
                        {
                            Name = record.Element(ns + "Name")?.Value ?? "",
                            Type = type,
                            Ttl = int.Parse(record.Element(ns + "TTL")?.Value ?? "0"),
                            Values = record.Descendants(ns + "Value").Select(v => v.Value).ToList()
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "列出 AWS Route 53 TXT 记录失败");
        }
        return records;
    }

    private async Task<bool> DeleteRecord(string hostedZoneId, AwsDnsRecord record, string accessKeyId, string secretAccessKey, string region)
    {
        try
        {
            var valuesXml = string.Join("", record.Values.Select(v => $"<Value>{v}</Value>"));
            var changeXml = $@"<?xml version=""1.0"" encoding=""UTF-8""?>
<ChangeResourceRecordSetsRequest xmlns=""https://route53.amazonaws.com/doc/2013-04-01/"">
    <ChangeBatch>
        <Changes>
            <Change>
                <Action>DELETE</Action>
                <ResourceRecordSet>
                    <Name>{record.Name}</Name>
                    <Type>{record.Type}</Type>
                    <TTL>{record.Ttl}</TTL>
                    <ResourceRecords>
                        {valuesXml}
                    </ResourceRecords>
                </ResourceRecordSet>
            </Change>
        </Changes>
    </ChangeBatch>
</ChangeResourceRecordSetsRequest>";

            var endpoint = $"https://route53.amazonaws.com/2013-04-01/hostedzone/{hostedZoneId}/rrset";
            var response = await SendAwsRequestAsync("POST", endpoint, changeXml, accessKeyId, secretAccessKey, region);

            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除 AWS Route 53 记录失败");
            return false;
        }
    }

    #endregion
}

#region AWS API 响应模型

public sealed class AwsHostedZone
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
}

public sealed class AwsDnsRecord
{
    public string Name { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public int Ttl { get; set; }
    public List<string> Values { get; set; } = new();
}

#endregion
