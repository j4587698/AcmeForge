using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AcmeForge.Dns;

/// <summary>
/// 阿里云 DNS API 提供商实现
/// </summary>
public class AliyunDnsProvider : IDnsProvider
{
    private readonly ILogger<AliyunDnsProvider> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;

    public AliyunDnsProvider(
        ILogger<AliyunDnsProvider> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _httpClient = _httpClientFactory.CreateClient("Aliyun");
        _httpClient.BaseAddress = new Uri("https://alidns.aliyuncs.com/");
    }

    public string Name => "aliyun";
    public string DisplayName => "阿里云DNS";
    public bool RequiresCredentials => true;

    /// <summary>
    /// 创建 DNS TXT 记录
    /// </summary>
    public async Task<DnsOperationResult> CreateTxtRecordAsync(string domain, string recordName, string recordValue, IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            _logger.LogInformation("创建阿里云 DNS TXT 记录: {RecordName} = {RecordValue}", recordName, recordValue);

            var accessKeyId = GetAccessKeyId(credentials);
            var accessKeySecret = GetAccessKeySecret(credentials);

            if (string.IsNullOrEmpty(accessKeyId) || string.IsNullOrEmpty(accessKeySecret))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = "阿里云 Access Key 未提供",
                    ErrorCode = "MISSING_CREDENTIALS"
                };
            }

            // 获取域名信息
            var domainName = DnsDomainHelper.ExtractRootDomain(domain);
            var domainRecordId = await GetDomainRecordId(domainName);
            if (string.IsNullOrEmpty(domainRecordId))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"无法获取域名 {domainName} 的记录ID",
                    ErrorCode = "DOMAIN_NOT_FOUND"
                };
            }

            // 检查记录是否已存在
            var existingRecord = await GetExistingTxtRecord(domainName, recordName, accessKeyId, accessKeySecret);
            if (existingRecord != null)
            {
                // 更新现有记录
                return await UpdateTxtRecord(domainName, existingRecord.RecordId, recordName, recordValue, accessKeyId, accessKeySecret);
            }

            // 创建新记录
            var parameters = new Dictionary<string, string>
            {
                ["Action"] = "AddDomainRecord",
                ["DomainName"] = domainName,
                ["RR"] = ExtractRR(recordName, domainName),
                ["Type"] = "TXT",
                ["Value"] = recordValue,
                ["TTL"] = "120"
            };

            var response = await SendRequestAsync(parameters, accessKeyId, accessKeySecret);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("创建阿里云 DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"创建 DNS 记录失败: {response.StatusCode}",
                    ErrorCode = "CREATE_FAILED",
                    Details = responseContent
                };
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.AliyunDnsResponse);
            // 阿里云 RPC 成功响应不含 Success 字段（仅 RequestId/RecordId），失败返回非 2xx，故 HTTP 200 即成功。
            if (result != null)
            {
                _logger.LogInformation("阿里云 DNS TXT 记录创建成功: {RecordName}", recordName);
                return new DnsOperationResult
                {
                    Success = true,
                    Message = "DNS 记录创建成功",
                    RecordId = result.RecordId,
                    Details = $"记录 ID: {result.RecordId}"
                };
            }

            return new DnsOperationResult
            {
                Success = false,
                Message = "创建 DNS 记录失败",
                ErrorCode = "API_ERROR",
                Details = responseContent
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建阿里云 DNS 记录异常: {RecordName}", recordName);
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
            _logger.LogInformation("删除阿里云 DNS TXT 记录: {RecordName}", recordName);

            var accessKeyId = GetAccessKeyId(credentials);
            var accessKeySecret = GetAccessKeySecret(credentials);

            if (string.IsNullOrEmpty(accessKeyId) || string.IsNullOrEmpty(accessKeySecret))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = "阿里云 Access Key 未提供",
                    ErrorCode = "MISSING_CREDENTIALS"
                };
            }

            // 获取域名信息
            var domainName = DnsDomainHelper.ExtractRootDomain(domain);
            var existingRecord = await GetExistingTxtRecord(domainName, recordName, accessKeyId, accessKeySecret);
            if (existingRecord == null)
            {
                _logger.LogWarning("未找到要删除的 DNS 记录: {RecordName}", recordName);
                return new DnsOperationResult
                {
                    Success = true,
                    Message = "记录不存在，无需删除"
                };
            }

            // 删除记录
            var parameters = new Dictionary<string, string>
            {
                ["Action"] = "DeleteDomainRecord",
                ["RecordId"] = existingRecord.RecordId
            };

            var response = await SendRequestAsync(parameters, accessKeyId, accessKeySecret);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("删除阿里云 DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"删除 DNS 记录失败: {response.StatusCode}",
                    ErrorCode = "DELETE_FAILED",
                    Details = responseContent
                };
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.AliyunDnsResponse);
            if (result != null)
            {
                _logger.LogInformation("阿里云 DNS TXT 记录删除成功: {RecordName}", recordName);
                return new DnsOperationResult
                {
                    Success = true,
                    Message = "DNS 记录删除成功",
                    RecordId = existingRecord.RecordId
                };
            }

            return new DnsOperationResult
            {
                Success = false,
                Message = "删除 DNS 记录失败",
                ErrorCode = "API_ERROR",
                Details = responseContent
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除阿里云 DNS 记录异常: {RecordName}", recordName);
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
            _logger.LogInformation("测试阿里云 DNS 连接");

            var accessKeyId = GetAccessKeyId(credentials);
            var accessKeySecret = GetAccessKeySecret(credentials);

            if (string.IsNullOrEmpty(accessKeyId) || string.IsNullOrEmpty(accessKeySecret))
            {
                return new DnsTestResult
                {
                    Success = false,
                    Message = "阿里云 Access Key 未提供",
                    ErrorCode = "MISSING_CREDENTIALS"
                };
            }

            // 测试获取域名列表
            var parameters = new Dictionary<string, string>
            {
                ["Action"] = "DescribeDomains",
                ["PageSize"] = "1"
            };

            var response = await SendRequestAsync(parameters, accessKeyId, accessKeySecret);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("阿里云 API 认证失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsTestResult
                {
                    Success = false,
                    Message = $"API 认证失败: {response.StatusCode}",
                    ErrorCode = "AUTH_FAILED",
                    Details = responseContent
                };
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.AliyunDomainsResponse);
            if (result != null)
            {
                var domainCount = result.Domains?.Domain?.Count ?? 0;
                return new DnsTestResult
                {
                    Success = true,
                    Message = "阿里云 API 连接测试成功",
                    Details = $"找到 {domainCount} 个域名"
                };
            }

            return new DnsTestResult
            {
                Success = false,
                Message = "API 连接测试失败",
                ErrorCode = "API_ERROR",
                Details = responseContent
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "测试阿里云 DNS 连接异常");
            return new DnsTestResult
            {
                Success = false,
                Message = $"连接测试异常: {ex.Message}",
                ErrorCode = "EXCEPTION",
                Details = ex.ToString()
            };
        }
    }

    #region 私有方法

    private string? GetAccessKeyId(IReadOnlyDictionary<string, object?>? credentials)
    {
        return credentials?.GetValueOrDefault("access_key_id")?.ToString()
               ?? _configuration["DnsProviders:Aliyun:AccessKeyId"];
    }

    private string? GetAccessKeySecret(IReadOnlyDictionary<string, object?>? credentials)
    {
        return credentials?.GetValueOrDefault("access_key_secret")?.ToString()
               ?? _configuration["DnsProviders:Aliyun:AccessKeySecret"];
    }

    private async Task<string?> GetDomainRecordId(string domainName)
    {
        try
        {
            // 阿里云 DNS API 使用域名名作为标识，不需要单独获取记录ID
            return domainName;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取域名记录ID异常: {Domain}", domainName);
            return null;
        }
    }

    private async Task<AliyunDnsRecord?> GetExistingTxtRecord(string domainName, string recordName, string accessKeyId, string accessKeySecret)
    {
        try
        {
            var parameters = new Dictionary<string, string>
            {
                ["Action"] = "DescribeDomainRecords",
                ["DomainName"] = domainName,
                ["TypeKeyWord"] = "TXT",
                ["RRKeyWord"] = ExtractRR(recordName, domainName)
            };

            var response = await SendRequestAsync(parameters, accessKeyId, accessKeySecret);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("查询现有 DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return null;
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.AliyunRecordsResponse);
            return result?.DomainRecords?.Record?.FirstOrDefault();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "查询现有 DNS 记录异常: {RecordName}", recordName);
            return null;
        }
    }

    private async Task<DnsOperationResult> UpdateTxtRecord(string domainName, string recordId, string recordName, string recordValue, string accessKeyId, string accessKeySecret)
    {
        try
        {
            var parameters = new Dictionary<string, string>
            {
                ["Action"] = "ModifyDomainRecord",
                ["RecordId"] = recordId,
                ["RR"] = ExtractRR(recordName, domainName),
                ["Type"] = "TXT",
                ["Value"] = recordValue,
                ["TTL"] = "120"
            };

            var response = await SendRequestAsync(parameters, accessKeyId, accessKeySecret);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("更新阿里云 DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"更新 DNS 记录失败: {response.StatusCode}",
                    ErrorCode = "UPDATE_FAILED",
                    Details = responseContent
                };
            }

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.AliyunDnsResponse);
            if (result != null)
            {
                _logger.LogInformation("阿里云 DNS TXT 记录更新成功: {RecordName}", recordName);
                return new DnsOperationResult
                {
                    Success = true,
                    Message = "DNS 记录更新成功",
                    RecordId = recordId,
                    Details = $"记录 ID: {recordId}"
                };
            }

            return new DnsOperationResult
            {
                Success = false,
                Message = "更新 DNS 记录失败",
                ErrorCode = "API_ERROR",
                Details = responseContent
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "更新阿里云 DNS 记录异常: {RecordName}", recordName);
            return new DnsOperationResult
            {
                Success = false,
                Message = $"更新 DNS 记录异常: {ex.Message}",
                ErrorCode = "EXCEPTION",
                Details = ex.ToString()
            };
        }
    }

    private async Task<HttpResponseMessage> SendRequestAsync(Dictionary<string, string> parameters, string accessKeyId, string accessKeySecret)
    {
        // 添加公共参数
        parameters["Format"] = "JSON";
        parameters["Version"] = "2015-01-09";
        parameters["AccessKeyId"] = accessKeyId;
        parameters["SignatureMethod"] = "HMAC-SHA1";
        parameters["Timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        parameters["SignatureVersion"] = "1.0";
        parameters["SignatureNonce"] = Guid.NewGuid().ToString("N");

        // 生成签名
        var signature = GenerateSignature(parameters, accessKeySecret);
        parameters["Signature"] = signature;

        // 构建查询字符串
        var queryString = string.Join("&", parameters.OrderBy(x => x.Key).Select(x => $"{Uri.EscapeDataString(x.Key)}={Uri.EscapeDataString(x.Value)}"));

        return await _httpClient.GetAsync($"?{queryString}");
    }

    private string GenerateSignature(Dictionary<string, string> parameters, string accessKeySecret)
    {
        var sortedParams = parameters.OrderBy(x => x.Key);
        var canonicalizedQueryString = string.Join("&", sortedParams.Select(x => $"{Uri.EscapeDataString(x.Key)}={Uri.EscapeDataString(x.Value)}"));

        var stringToSign = $"GET&%2F&{Uri.EscapeDataString(canonicalizedQueryString)}";

        using var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(accessKeySecret + "&"));
        var signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));

        return Convert.ToBase64String(signatureBytes);
    }

    private string ExtractRR(string recordName, string domainName)
    {
        if (recordName.EndsWith(domainName))
        {
            var rr = recordName[..^domainName.Length].TrimEnd('.');
            return string.IsNullOrEmpty(rr) ? "@" : rr;
        }
        return recordName;
    }

    /// <summary>
    /// 删除所有匹配名称的 DNS TXT 记录（默认实现：逐个删除）
    /// </summary>
    public async Task<DnsOperationResult> DeleteAllTxtRecordsByNameAsync(string domain, string recordName, IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            _logger.LogInformation("阿里云: 删除所有匹配的 DNS TXT 记录: {RecordName}", recordName);

            var accessKeyId = GetAccessKeyId(credentials);
            var accessKeySecret = GetAccessKeySecret(credentials);

            if (string.IsNullOrEmpty(accessKeyId) || string.IsNullOrEmpty(accessKeySecret))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = "缺少阿里云 API 凭证",
                    ErrorCode = "MISSING_CREDENTIALS"
                };
            }

            var domainName = DnsDomainHelper.ExtractRootDomain(domain);
            var domainId = await GetDomainId(domainName, accessKeyId, accessKeySecret);

            if (string.IsNullOrEmpty(domainId))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"无法获取域名 {domainName} 的 ID",
                    ErrorCode = "DOMAIN_NOT_FOUND"
                };
            }

            // 获取所有匹配的 TXT 记录
            var records = await ListTxtRecords(domainId, domainName, recordName, accessKeyId, accessKeySecret);
            if (records == null || records.Count == 0)
            {
                return new DnsOperationResult
                {
                    Success = true,
                    Message = "没有找到匹配的记录"
                };
            }

            var deletedCount = 0;
            foreach (var record in records)
            {
                var deleteResult = await DeleteRecord(domainId, record.RecordId, accessKeyId, accessKeySecret);
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
            _logger.LogError(ex, "阿里云删除所有 DNS TXT 记录时发生错误: {RecordName}", recordName);
            return new DnsOperationResult
            {
                Success = false,
                Message = $"删除 DNS TXT 记录时发生错误: {ex.Message}",
                ErrorCode = "EXCEPTION"
            };
        }
    }

    /// <summary>
    /// 获取域名 ID
    /// </summary>
    private async Task<string?> GetDomainId(string domainName, string accessKeyId, string accessKeySecret)
    {
        try
        {
            var parameters = new Dictionary<string, string>
            {
                ["Action"] = "DescribeDomains",
                ["PageSize"] = "100"
            };

            var response = await SendRequestAsync(parameters, accessKeyId, accessKeySecret);
            var responseContent = await response.Content.ReadAsStringAsync();

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.AliyunDomainsResponse);
            if (result?.Domains?.Domain != null)
            {
                var domain = result.Domains.Domain.FirstOrDefault(d =>
                    d.DomainName?.Equals(domainName, StringComparison.OrdinalIgnoreCase) == true);
                return domain?.DomainId;
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取域名 ID 时发生错误: {DomainName}", domainName);
            return null;
        }
    }

    /// <summary>
    /// 列出所有 TXT 记录
    /// </summary>
    private async Task<List<AliyunDnsRecord>> ListTxtRecords(string domainId, string domainName, string recordName, string accessKeyId, string accessKeySecret)
    {
        try
        {
            var rr = ExtractRR(recordName, domainName);
            var parameters = new Dictionary<string, string>
            {
                ["Action"] = "DescribeDomainRecords",
                ["DomainName"] = domainName,
                ["RRKeyWord"] = rr,
                ["TypeKeyWord"] = "TXT"
            };

            var response = await SendRequestAsync(parameters, accessKeyId, accessKeySecret);
            var responseContent = await response.Content.ReadAsStringAsync();

            var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.AliyunRecordsResponse);
            return result?.DomainRecords?.Record?.Where(r => r.RR == rr && r.Type == "TXT").ToList() ?? new List<AliyunDnsRecord>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "列出 TXT 记录时发生错误: {RecordName}", recordName);
            return new List<AliyunDnsRecord>();
        }
    }

    /// <summary>
    /// 删除 DNS 记录
    /// </summary>
    private async Task<bool> DeleteRecord(string domainId, string recordId, string accessKeyId, string accessKeySecret)
    {
        try
        {
            var parameters = new Dictionary<string, string>
            {
                ["Action"] = "DeleteDomainRecord",
                ["RecordId"] = recordId
            };

            var response = await SendRequestAsync(parameters, accessKeyId, accessKeySecret);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除 DNS 记录时发生错误: {RecordId}", recordId);
            return false;
        }
    }

    #endregion
}

#region 阿里云 API 响应模型

public sealed class AliyunDnsResponse
{
    [JsonPropertyName("RequestId")] public string RequestId { get; set; } = string.Empty;
    [JsonPropertyName("Success")] public bool Success { get; set; }
    [JsonPropertyName("RecordId")] public string? RecordId { get; set; }
    [JsonPropertyName("Code")] public string? Code { get; set; }
    [JsonPropertyName("Message")] public string? Message { get; set; }
}

public sealed class AliyunDomainsResponse
{
    [JsonPropertyName("RequestId")] public string RequestId { get; set; } = string.Empty;
    [JsonPropertyName("Success")] public bool Success { get; set; }
    [JsonPropertyName("Domains")] public AliyunDomainSet? Domains { get; set; }
    [JsonPropertyName("Code")] public string? Code { get; set; }
    [JsonPropertyName("Message")] public string? Message { get; set; }
}

public sealed class AliyunDomainSet
{
    [JsonPropertyName("Domain")] public List<AliyunDomain>? Domain { get; set; }
}

public sealed class AliyunRecordsResponse
{
    [JsonPropertyName("RequestId")] public string RequestId { get; set; } = string.Empty;
    [JsonPropertyName("Success")] public bool Success { get; set; }
    [JsonPropertyName("TotalCount")] public int TotalCount { get; set; }
    [JsonPropertyName("DomainRecords")] public AliyunRecordSet? DomainRecords { get; set; }
    [JsonPropertyName("Code")] public string? Code { get; set; }
    [JsonPropertyName("Message")] public string? Message { get; set; }
}

public sealed class AliyunRecordSet
{
    [JsonPropertyName("Record")] public List<AliyunDnsRecord>? Record { get; set; }
}

public sealed class AliyunDomain
{
    [JsonPropertyName("DomainId")] public string DomainId { get; set; } = string.Empty;
    [JsonPropertyName("DomainName")] public string DomainName { get; set; } = string.Empty;
    [JsonPropertyName("PunyCode")] public string PunyCode { get; set; } = string.Empty;
    [JsonPropertyName("DnsServers")] public List<string>? DnsServers { get; set; }
    [JsonPropertyName("DomainAuditStatus")] public string DomainAuditStatus { get; set; } = string.Empty;
    [JsonPropertyName("DomainAuditFailReason")] public string DomainAuditFailReason { get; set; } = string.Empty;
    [JsonPropertyName("CreateTime")] public DateTime? CreateTime { get; set; }
    [JsonPropertyName("ExpireTime")] public DateTime? ExpireTime { get; set; }
    [JsonPropertyName("RecordCount")] public int RecordCount { get; set; }
}

public sealed class AliyunDnsRecord
{
    [JsonPropertyName("RecordId")] public string RecordId { get; set; } = string.Empty;
    [JsonPropertyName("DomainId")] public string DomainId { get; set; } = string.Empty;
    [JsonPropertyName("DomainName")] public string DomainName { get; set; } = string.Empty;
    [JsonPropertyName("RR")] public string RR { get; set; } = string.Empty;
    [JsonPropertyName("Type")] public string Type { get; set; } = string.Empty;
    [JsonPropertyName("Value")] public string Value { get; set; } = string.Empty;
    [JsonPropertyName("TTL")] public int TTL { get; set; }
    [JsonPropertyName("Priority")] public int Priority { get; set; }
    [JsonPropertyName("Line")] public string Line { get; set; } = string.Empty;
    [JsonPropertyName("Status")] public string Status { get; set; } = string.Empty;
    [JsonPropertyName("Locked")] public bool Locked { get; set; }
}

#endregion
