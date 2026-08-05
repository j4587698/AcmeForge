using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AcmeForge.Dns;

/// <summary>
/// 腾讯云 DNS API (TC3-HMAC-SHA256) 提供商。
/// </summary>
public class TencentDnsProvider : IDnsProvider
{
    private readonly ILogger<TencentDnsProvider> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;

    public TencentDnsProvider(
        ILogger<TencentDnsProvider> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _httpClient = _httpClientFactory.CreateClient("Tencent");
        _httpClient.BaseAddress = new Uri("https://dnspod.tencentcloudapi.com/");
    }

    public string Name => "tencent";
    public string DisplayName => "腾讯云DNS";
    public bool RequiresCredentials => true;

    public async Task<DnsOperationResult> CreateTxtRecordAsync(
        string domain,
        string recordName,
        string recordValue,
        IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            _logger.LogInformation("创建腾讯云 DNS TXT 记录: {RecordName} = {RecordValue}", recordName, recordValue);

            var secretId = GetSecretId(credentials);
            var secretKey = GetSecretKey(credentials);

            if (string.IsNullOrEmpty(secretId) || string.IsNullOrEmpty(secretKey))
            {
                return new DnsOperationResult { Success = false, Message = "腾讯云 Secret 未提供", ErrorCode = "MISSING_CREDENTIALS" };
            }

            var domainName = DnsDomainHelper.ExtractRootDomain(domain);
            var domainId = await GetDomainId(domainName, secretId, secretKey);
            if (string.IsNullOrEmpty(domainId))
            {
                return new DnsOperationResult { Success = false, Message = $"无法获取域名 {domainName} 的 ID", ErrorCode = "DOMAIN_NOT_FOUND" };
            }

            var existingRecord = await GetExistingTxtRecord(domainName, domainId, recordName, secretId, secretKey);
            if (existingRecord != null && !string.IsNullOrEmpty(existingRecord.RecordId))
            {
                return await UpdateTxtRecord(domainName, domainId, existingRecord.RecordId!, recordName, recordValue, secretId, secretKey);
            }

            var response = await CreateRecordRequest(domainName, domainId, recordName, recordValue, secretId, secretKey);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("创建腾讯云 DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult { Success = false, Message = $"创建 DNS 记录失败: {response.StatusCode}", ErrorCode = "CREATE_FAILED", Details = responseContent };
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.TencentDnsResponse);
            if (result?.Response?.Error == null && result?.Response != null)
            {
                var recordId = result.Response.RecordId ?? string.Empty;
                _logger.LogInformation("腾讯云 DNS TXT 记录创建成功: {RecordName}", recordName);
                return new DnsOperationResult { Success = true, Message = "DNS 记录创建成功", RecordId = recordId, Details = $"记录 ID: {recordId}" };
            }

            return new DnsOperationResult { Success = false, Message = $"创建 DNS 记录失败: {result?.Response?.Error?.Message}", ErrorCode = result?.Response?.Error?.Code ?? "API_ERROR", Details = responseContent };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建腾讯云 DNS 记录异常: {RecordName}", recordName);
            return new DnsOperationResult { Success = false, Message = $"创建 DNS 记录异常: {ex.Message}", ErrorCode = "EXCEPTION", Details = ex.ToString() };
        }
    }

    public async Task<DnsOperationResult> DeleteTxtRecordAsync(
        string domain,
        string recordName,
        string recordValue,
        IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            _logger.LogInformation("删除腾讯云 DNS TXT 记录: {RecordName}", recordName);

            var secretId = GetSecretId(credentials);
            var secretKey = GetSecretKey(credentials);

            if (string.IsNullOrEmpty(secretId) || string.IsNullOrEmpty(secretKey))
            {
                return new DnsOperationResult { Success = false, Message = "腾讯云 Secret 未提供", ErrorCode = "MISSING_CREDENTIALS" };
            }

            var domainName = DnsDomainHelper.ExtractRootDomain(domain);
            var domainId = await GetDomainId(domainName, secretId, secretKey);
            if (string.IsNullOrEmpty(domainId))
            {
                return new DnsOperationResult { Success = false, Message = $"无法获取域名 {domainName} 的 ID", ErrorCode = "DOMAIN_NOT_FOUND" };
            }

            var existingRecord = await GetExistingTxtRecord(domainName, domainId, recordName, secretId, secretKey);
            if (existingRecord == null)
            {
                _logger.LogWarning("未找到要删除的 DNS 记录: {RecordName}", recordName);
                return new DnsOperationResult { Success = true, Message = "记录不存在，无需删除" };
            }

            if (string.IsNullOrEmpty(existingRecord.RecordId))
            {
                _logger.LogWarning("DNS 记录 ID 为空，无法删除: {RecordName}", recordName);
                return new DnsOperationResult { Success = false, Message = "记录 ID 为空，无法删除" };
            }

            var response = await DeleteRecordRequest(domainId, existingRecord.RecordId!, secretId, secretKey);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("删除腾讯云 DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult { Success = false, Message = $"删除 DNS 记录失败: {response.StatusCode}", ErrorCode = "DELETE_FAILED", Details = responseContent };
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.TencentDnsResponse);
            if (result?.Response?.Error == null)
            {
                _logger.LogInformation("腾讯云 DNS TXT 记录删除成功: {RecordName}", recordName);
                return new DnsOperationResult { Success = true, Message = "DNS 记录删除成功", RecordId = existingRecord.RecordId };
            }

            return new DnsOperationResult { Success = false, Message = $"删除 DNS 记录失败: {result.Response?.Error?.Message}", ErrorCode = result.Response?.Error?.Code ?? "API_ERROR", Details = responseContent };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除腾讯云 DNS 记录异常: {RecordName}", recordName);
            return new DnsOperationResult { Success = false, Message = $"删除 DNS 记录异常: {ex.Message}", ErrorCode = "EXCEPTION", Details = ex.ToString() };
        }
    }

    public async Task<DnsTestResult> TestConnectionAsync(IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            _logger.LogInformation("测试腾讯云 DNS 连接");

            var secretId = GetSecretId(credentials);
            var secretKey = GetSecretKey(credentials);

            if (string.IsNullOrEmpty(secretId) || string.IsNullOrEmpty(secretKey))
            {
                return new DnsTestResult { Success = false, Message = "腾讯云 Secret 未提供", ErrorCode = "MISSING_CREDENTIALS" };
            }

            var response = await DescribeDomainsRequest(secretId, secretKey);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("腾讯云 API 认证失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsTestResult { Success = false, Message = $"API 认证失败: {response.StatusCode}", ErrorCode = "AUTH_FAILED", Details = responseContent };
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.TencentDomainsResponse);
            if (result?.Response?.Error == null && result?.Response != null)
            {
                var domainCount = result.Response.DomainCountInfo?.AllTotal ?? 0;
                return new DnsTestResult { Success = true, Message = "腾讯云 API 连接测试成功", Details = $"找到 {domainCount} 个域名" };
            }

            return new DnsTestResult { Success = false, Message = $"API 连接测试失败: {result?.Response?.Error?.Message}", ErrorCode = result?.Response?.Error?.Code ?? "API_ERROR", Details = responseContent };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "测试腾讯云 DNS 连接异常");
            return new DnsTestResult { Success = false, Message = $"连接测试异常: {ex.Message}", ErrorCode = "EXCEPTION", Details = ex.ToString() };
        }
    }

    public async Task<DnsOperationResult> DeleteAllTxtRecordsByNameAsync(
        string domain,
        string recordName,
        IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            _logger.LogInformation("腾讯云: 删除所有匹配的 DNS TXT 记录: {RecordName}", recordName);

            var secretId = GetSecretId(credentials);
            var secretKey = GetSecretKey(credentials);

            if (string.IsNullOrEmpty(secretId) || string.IsNullOrEmpty(secretKey))
            {
                return new DnsOperationResult { Success = false, Message = "缺少腾讯云 API 凭证", ErrorCode = "MISSING_CREDENTIALS" };
            }

            var domainName = DnsDomainHelper.ExtractRootDomain(domain);
            var domainId = await GetDomainId(domainName, secretId, secretKey);

            if (string.IsNullOrEmpty(domainId))
            {
                return new DnsOperationResult { Success = false, Message = $"无法获取域名 {domainName} 的 ID", ErrorCode = "DOMAIN_NOT_FOUND" };
            }

            var records = await ListTxtRecords(domainId, domainName, recordName, secretId, secretKey);
            if (records == null || records.Count == 0)
            {
                return new DnsOperationResult { Success = true, Message = "没有找到匹配的记录" };
            }

            var deletedCount = 0;
            foreach (var record in records)
            {
                if (!string.IsNullOrEmpty(record.RecordId) && await DeleteRecord(domainId, record.RecordId, secretId, secretKey))
                {
                    deletedCount++;
                }
            }

            return new DnsOperationResult { Success = true, Message = $"成功删除 {deletedCount} 条 DNS TXT 记录", Details = $"已删除 {deletedCount} 条记录" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "腾讯云删除所有 DNS TXT 记录时发生错误: {RecordName}", recordName);
            return new DnsOperationResult { Success = false, Message = $"删除 DNS TXT 记录时发生错误: {ex.Message}", ErrorCode = "EXCEPTION" };
        }
    }

    private string? GetSecretId(IReadOnlyDictionary<string, object?>? credentials)
        => credentials?.GetValueOrDefault("secret_id")?.ToString()
           ?? credentials?.GetValueOrDefault("secretId")?.ToString()
           ?? _configuration["DnsProviders:Tencent:SecretId"];

    private string? GetSecretKey(IReadOnlyDictionary<string, object?>? credentials)
        => credentials?.GetValueOrDefault("secret_key")?.ToString()
           ?? credentials?.GetValueOrDefault("secretKey")?.ToString()
           ?? _configuration["DnsProviders:Tencent:SecretKey"];

    private async Task<string?> GetDomainId(string domainName, string secretId, string secretKey)
    {
        try
        {
            var response = await DescribeDomainsRequest(secretId, secretKey);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("获取域名列表失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return null;
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.TencentDomainsResponse);
            var domain = result?.Response?.DomainList?.FirstOrDefault(d =>
                d.DomainName?.Equals(domainName, StringComparison.OrdinalIgnoreCase) == true);

            return domain?.DomainId;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取域名ID异常: {Domain}", domainName);
            return null;
        }
    }

    private async Task<TencentDnsRecord?> GetExistingTxtRecord(string domainName, string domainId, string recordName, string secretId, string secretKey)
    {
        try
        {
            var response = await DescribeRecordListRequest(domainName, domainId, recordName, secretId, secretKey);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("查询现有 DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return null;
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.TencentRecordsResponse);
            return result?.Response?.RecordList?.FirstOrDefault();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "查询现有 DNS 记录异常: {RecordName}", recordName);
            return null;
        }
    }

    private async Task<DnsOperationResult> UpdateTxtRecord(string domainName, string domainId, string recordId, string recordName, string recordValue, string secretId, string secretKey)
    {
        try
        {
            var response = await ModifyRecordRequest(domainName, domainId, recordId, recordName, recordValue, secretId, secretKey);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("更新腾讯云 DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult { Success = false, Message = $"更新 DNS 记录失败: {response.StatusCode}", ErrorCode = "UPDATE_FAILED", Details = responseContent };
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.TencentDnsResponse);
            if (result?.Response?.Error == null)
            {
                _logger.LogInformation("腾讯云 DNS TXT 记录更新成功: {RecordName}", recordName);
                return new DnsOperationResult { Success = true, Message = "DNS 记录更新成功", RecordId = recordId, Details = $"记录 ID: {recordId}" };
            }

            return new DnsOperationResult { Success = false, Message = $"更新 DNS 记录失败: {result.Response?.Error?.Message}", ErrorCode = result.Response?.Error?.Code ?? "API_ERROR", Details = responseContent };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "更新腾讯云 DNS 记录异常: {RecordName}", recordName);
            return new DnsOperationResult { Success = false, Message = $"更新 DNS 记录异常: {ex.Message}", ErrorCode = "EXCEPTION", Details = ex.ToString() };
        }
    }

    private async Task<HttpResponseMessage> CreateRecordRequest(string domainName, string domainId, string recordName, string recordValue, string secretId, string secretKey)
    {
        var body = new TencentCreateRecordRequest
        {
            DomainId = domainId,
            SubDomain = DnsDomainHelper.ExtractSubDomain(recordName, domainName),
            RecordType = "TXT",
            RecordLine = "默认",
            RecordValue = recordValue,
            TTL = 120,
        };
        var jsonBody = JsonSerializer.Serialize(body, DnsJsonContext.Instance.TencentCreateRecordRequest);
        return await SendRequestAsync("CreateRecord", jsonBody, secretId, secretKey);
    }

    private async Task<HttpResponseMessage> DeleteRecordRequest(string domainId, string recordId, string secretId, string secretKey)
    {
        var body = new TencentDeleteRecordRequest { DomainId = domainId, RecordId = recordId };
        var jsonBody = JsonSerializer.Serialize(body, DnsJsonContext.Instance.TencentDeleteRecordRequest);
        return await SendRequestAsync("DeleteRecord", jsonBody, secretId, secretKey);
    }

    private async Task<HttpResponseMessage> ModifyRecordRequest(string domainName, string domainId, string recordId, string recordName, string recordValue, string secretId, string secretKey)
    {
        var body = new TencentModifyRecordRequest
        {
            DomainId = domainId,
            RecordId = recordId,
            SubDomain = DnsDomainHelper.ExtractSubDomain(recordName, domainName),
            RecordType = "TXT",
            RecordLine = "默认",
            RecordValue = recordValue,
            TTL = 120,
        };
        var jsonBody = JsonSerializer.Serialize(body, DnsJsonContext.Instance.TencentModifyRecordRequest);
        return await SendRequestAsync("ModifyRecord", jsonBody, secretId, secretKey);
    }

    private async Task<HttpResponseMessage> DescribeDomainsRequest(string secretId, string secretKey)
    {
        return await SendRequestAsync("DescribeDomainList", "{}", secretId, secretKey);
    }

    private async Task<HttpResponseMessage> DescribeRecordListRequest(string domainName, string domainId, string recordName, string secretId, string secretKey)
    {
        var body = new TencentDescribeRecordListRequest
        {
            DomainId = domainId,
            Subdomain = DnsDomainHelper.ExtractSubDomain(recordName, domainName),
            RecordType = "TXT",
        };
        var jsonBody = JsonSerializer.Serialize(body, DnsJsonContext.Instance.TencentDescribeRecordListRequest);
        return await SendRequestAsync("DescribeRecordList", jsonBody, secretId, secretKey);
    }

    private async Task<HttpResponseMessage> SendRequestAsync(string action, string jsonBody, string secretId, string secretKey)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var host = _httpClient.BaseAddress!.Host;

        var signature = GenerateTencentSignature(action, "2021-03-23", timestamp, jsonBody, secretKey, secretId, host);

        using var request = new HttpRequestMessage(HttpMethod.Post, string.Empty);
        request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
        request.Headers.TryAddWithoutValidation("Host", host);
        request.Headers.TryAddWithoutValidation("X-TC-Action", action);
        request.Headers.TryAddWithoutValidation("X-TC-Version", "2021-03-23");
        request.Headers.TryAddWithoutValidation("X-TC-Timestamp", timestamp.ToString());
        request.Headers.TryAddWithoutValidation("X-TC-Region", string.Empty);
        request.Headers.TryAddWithoutValidation("Authorization", signature);

        _logger.LogInformation("腾讯云 DNS API 请求: Action={Action}, Timestamp={Timestamp}", action, timestamp);

        return await _httpClient.SendAsync(request);
    }

    private static string GenerateTencentSignature(string action, string version, long timestamp, string body, string secretKey, string secretId, string host)
    {
        var contentType = "application/json; charset=utf-8";
        const string canonicalUri = "/";
        var canonicalHeaders = "content-type:" + contentType + "\nhost:" + host + "\n";
        const string signedHeaders = "content-type;host";

        var hashedRequestPayload = Sha256Hex(body);
        var canonicalRequest = "POST\n"
                               + canonicalUri + "\n"
                               + "\n"
                               + canonicalHeaders + "\n"
                               + signedHeaders + "\n"
                               + hashedRequestPayload;

        const string algorithm = "TC3-HMAC-SHA256";
        var date = DateTimeOffset.FromUnixTimeSeconds(timestamp).UtcDateTime.ToString("yyyy-MM-dd");
        const string service = "dnspod";
        var credentialScope = date + "/" + service + "/" + "tc3_request";
        var hashedCanonicalRequest = Sha256Hex(canonicalRequest);
        var stringToSign = algorithm + "\n"
                                       + timestamp.ToString() + "\n"
                                       + credentialScope + "\n"
                                       + hashedCanonicalRequest;

        var tc3SecretKey = Encoding.UTF8.GetBytes("TC3" + secretKey);
        var secretDate = HmacSha256(tc3SecretKey, Encoding.UTF8.GetBytes(date));
        var secretService = HmacSha256(secretDate, Encoding.UTF8.GetBytes(service));
        var secretSigning = HmacSha256(secretService, Encoding.UTF8.GetBytes("tc3_request"));
        var signatureBytes = HmacSha256(secretSigning, Encoding.UTF8.GetBytes(stringToSign));
        var signature = Convert.ToHexStringLower(signatureBytes);

        return algorithm + " "
                         + "Credential=" + secretId + "/" + credentialScope + ", "
                         + "SignedHeaders=" + signedHeaders + ", "
                         + "Signature=" + signature;
    }

    private static string Sha256Hex(string s)
    {
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
    }

    private static byte[] HmacSha256(byte[] key, byte[] message)
    {
        return HMACSHA256.HashData(key, message);
    }

    private async Task<List<TencentDnsRecord>> ListTxtRecords(string domainId, string domainName, string recordName, string secretId, string secretKey)
    {
        try
        {
            var response = await DescribeRecordListRequest(domainName, domainId, recordName, secretId, secretKey);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("查询现有 DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new List<TencentDnsRecord>();
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.TencentRecordsResponse);
            return result?.Response?.RecordList?.Where(r => r.RecordType == "TXT").ToList() ?? new List<TencentDnsRecord>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "列出 TXT 记录时发生错误: {RecordName}", recordName);
            return new List<TencentDnsRecord>();
        }
    }

    private async Task<bool> DeleteRecord(string domainId, string recordId, string secretId, string secretKey)
    {
        try
        {
            var response = await DeleteRecordRequest(domainId, recordId, secretId, secretKey);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除 DNS 记录时发生错误: {RecordId}", recordId);
            return false;
        }
    }
}

public sealed class TencentDnsResponse
{
    public TencentResponse? Response { get; set; }
}

public sealed class TencentResponse
{
    public string? RequestId { get; set; }

    [JsonConverter(typeof(JsonStringOrNumberConverter))]
    public string? RecordId { get; set; }
    public TencentError? Error { get; set; }
}

public sealed class TencentDomainsResponse
{
    public TencentDomainsResponseData? Response { get; set; }
}

public sealed class TencentDomainsResponseData
{
    public string? RequestId { get; set; }

    [JsonPropertyName("DomainCountInfo")]
    public TencentDomainCountInfo? DomainCountInfo { get; set; }
    public List<TencentDomain>? DomainList { get; set; }
    public TencentError? Error { get; set; }
}

public sealed class TencentDomainCountInfo
{
    [JsonPropertyName("AllTotal")]
    public int? AllTotal { get; set; }
}

public sealed class TencentRecordsResponse
{
    public TencentRecordsResponseData? Response { get; set; }
}

public sealed class TencentRecordsResponseData
{
    public string? RequestId { get; set; }
    public int? TotalCount { get; set; }
    public List<TencentDnsRecord>? RecordList { get; set; }
    public TencentError? Error { get; set; }
}

public sealed class TencentDomain
{
    [JsonConverter(typeof(JsonStringOrNumberConverter))]
    public string? DomainId { get; set; }

    [JsonPropertyName("Name")]
    public string? DomainName { get; set; }
    public string? Status { get; set; }

    [JsonPropertyName("IsVip")]
    public string? IsVip { get; set; }
}

public sealed class TencentDnsRecord
{
    [JsonConverter(typeof(JsonStringOrNumberConverter))]
    public string? RecordId { get; set; }

    [JsonPropertyName("Name")]
    public string? SubDomain { get; set; }

    [JsonPropertyName("Type")]
    public string? RecordType { get; set; }

    [JsonPropertyName("Value")]
    public string? RecordValue { get; set; }
    public int? TTL { get; set; }
    public int? Weight { get; set; }
    public string? Status { get; set; }

    [JsonPropertyName("MX")]
    public int? Mx { get; set; }
}

public sealed class TencentError
{
    public string? Code { get; set; }
    public string? Message { get; set; }
}

public sealed class TencentCreateRecordRequest
{
    [JsonPropertyName("DomainId")]
    [JsonConverter(typeof(JsonStringAsNumberConverter))]
    public string DomainId { get; set; } = string.Empty;

    [JsonPropertyName("SubDomain")]
    public string SubDomain { get; set; } = string.Empty;

    [JsonPropertyName("RecordType")]
    public string RecordType { get; set; } = string.Empty;

    [JsonPropertyName("RecordLine")]
    public string RecordLine { get; set; } = string.Empty;

    [JsonPropertyName("RecordValue")]
    public string RecordValue { get; set; } = string.Empty;

    [JsonPropertyName("TTL")]
    public int TTL { get; set; }
}

public sealed class TencentDeleteRecordRequest
{
    [JsonPropertyName("DomainId")]
    [JsonConverter(typeof(JsonStringAsNumberConverter))]
    public string DomainId { get; set; } = string.Empty;

    [JsonPropertyName("RecordId")]
    [JsonConverter(typeof(JsonStringAsNumberConverter))]
    public string RecordId { get; set; } = string.Empty;
}

public sealed class TencentModifyRecordRequest
{
    [JsonPropertyName("DomainId")]
    [JsonConverter(typeof(JsonStringAsNumberConverter))]
    public string DomainId { get; set; } = string.Empty;

    [JsonPropertyName("RecordId")]
    [JsonConverter(typeof(JsonStringAsNumberConverter))]
    public string RecordId { get; set; } = string.Empty;

    [JsonPropertyName("SubDomain")]
    public string SubDomain { get; set; } = string.Empty;

    [JsonPropertyName("RecordType")]
    public string RecordType { get; set; } = string.Empty;

    [JsonPropertyName("RecordLine")]
    public string RecordLine { get; set; } = string.Empty;

    [JsonPropertyName("RecordValue")]
    public string RecordValue { get; set; } = string.Empty;

    [JsonPropertyName("TTL")]
    public int TTL { get; set; }
}

public sealed class TencentDescribeRecordListRequest
{
    [JsonPropertyName("DomainId")]
    public string DomainId { get; set; } = string.Empty;

    [JsonPropertyName("Subdomain")]
    public string Subdomain { get; set; } = string.Empty;

    [JsonPropertyName("RecordType")]
    public string RecordType { get; set; } = string.Empty;
}