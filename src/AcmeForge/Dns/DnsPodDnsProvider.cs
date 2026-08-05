using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AcmeForge.Dns;

/// <summary>
/// DNSPod 传统API (dnsapi.cn) 提供商实现
/// 使用旧版 DNSPod API 格式
/// </summary>
public class DnsPodDnsProvider : IDnsProvider
{
    private readonly ILogger<DnsPodDnsProvider> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;

    // 域名ID到域名的映射缓存
    private readonly Dictionary<string, string> _domainIdToNameMap = new();

    public DnsPodDnsProvider(
        ILogger<DnsPodDnsProvider> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _httpClient = _httpClientFactory.CreateClient("DnsPod");
        // 使用传统 DNSPod API
        _httpClient.BaseAddress = new Uri("https://dnsapi.cn/");
    }

    public string Name => "dnspod";
    public string DisplayName => "DNSPod";
    public bool RequiresCredentials => true;

    /// <summary>
    /// 创建 DNS TXT 记录
    /// </summary>
    public async Task<DnsOperationResult> CreateTxtRecordAsync(string domain, string recordName, string recordValue, IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            _logger.LogInformation("创建 DNSPod DNS TXT 记录: {RecordName} = {RecordValue}", recordName, recordValue);

            var secretId = GetSecretId(credentials);
            var secretKey = GetSecretKey(credentials);

            if (string.IsNullOrEmpty(secretId) || string.IsNullOrEmpty(secretKey))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = "DNSPod Secret 未提供",
                    ErrorCode = "MISSING_CREDENTIALS"
                };
            }

            // 构建 login_token
            var loginToken = $"{secretId},{secretKey}";

            // 获取域名信息
            var domainName = DnsDomainHelper.ExtractRootDomain(domain);
            var domainId = await GetDomainId(domainName, loginToken);

            if (string.IsNullOrEmpty(domainId))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"无法获取域名 {domainName} 的 ID",
                    ErrorCode = "DOMAIN_NOT_FOUND"
                };
            }

            // 缓存域名ID到域名的映射
            if (!_domainIdToNameMap.ContainsKey(domainId))
            {
                _domainIdToNameMap[domainId] = domainName;
            }

            // 提取子域名
            var subDomain = DnsDomainHelper.ExtractSubDomain(recordName, domainName);

            // 检查记录是否已存在
            var existingRecordId = await GetRecordId(domainId, subDomain, recordValue, loginToken);
            if (!string.IsNullOrEmpty(existingRecordId))
            {
                _logger.LogInformation("DNS TXT 记录已存在，跳过创建: {RecordName} = {RecordValue}, RecordId: {RecordId}",
                    recordName, recordValue, existingRecordId);
                return new DnsOperationResult
                {
                    Success = true,
                    Message = $"DNS TXT 记录已存在: {recordName} = {recordValue}",
                    RecordId = existingRecordId
                };
            }

            // 创建新记录
            var recordId = await CreateRecord(domainId, subDomain, recordValue, loginToken);

            if (!string.IsNullOrEmpty(recordId))
            {
                return new DnsOperationResult
                {
                    Success = true,
                    Message = $"DNS TXT 记录创建成功: {recordName} = {recordValue}",
                    RecordId = recordId
                };
            }
            else
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = "创建 DNS TXT 记录失败",
                    ErrorCode = "CREATE_FAILED"
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建 DNS TXT 记录时发生错误: {RecordName}", recordName);
            return new DnsOperationResult
            {
                Success = false,
                Message = $"创建 DNS TXT 记录时发生错误: {ex.Message}",
                ErrorCode = "EXCEPTION"
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
            _logger.LogInformation("删除 DNSPod DNS TXT 记录: {RecordName}", recordName);

            var secretId = GetSecretId(credentials);
            var secretKey = GetSecretKey(credentials);
            var loginToken = $"{secretId},{secretKey}";

            var domainName = DnsDomainHelper.ExtractRootDomain(domain);
            var domainId = await GetDomainId(domainName, loginToken);

            if (string.IsNullOrEmpty(domainId))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"无法获取域名 {domainName} 的 ID",
                    ErrorCode = "DOMAIN_NOT_FOUND"
                };
            }

            var subDomain = DnsDomainHelper.ExtractSubDomain(recordName, domainName);
            var recordId = await GetRecordId(domainId, subDomain, recordValue, loginToken);

            if (string.IsNullOrEmpty(recordId))
            {
                return new DnsOperationResult
                {
                    Success = true,
                    Message = "记录不存在，无需删除"
                };
            }

            var success = await DeleteRecord(domainId, recordId, loginToken);

            if (success)
            {
                return new DnsOperationResult
                {
                    Success = true,
                    Message = $"DNS TXT 记录删除成功: {recordName}",
                    RecordId = recordId
                };
            }
            else
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = "删除 DNS TXT 记录失败",
                    ErrorCode = "DELETE_FAILED"
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除 DNS TXT 记录时发生错误: {RecordName}", recordName);
            return new DnsOperationResult
            {
                Success = false,
                Message = $"删除 DNS TXT 记录时发生错误: {ex.Message}",
                ErrorCode = "EXCEPTION"
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
            _logger.LogInformation("删除所有匹配的 DNS TXT 记录: {RecordName}", recordName);

            var secretId = GetSecretId(credentials);
            var secretKey = GetSecretKey(credentials);
            var loginToken = $"{secretId},{secretKey}";

            var domainName = DnsDomainHelper.ExtractRootDomain(domain);
            var domainId = await GetDomainId(domainName, loginToken);

            if (string.IsNullOrEmpty(domainId))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"无法获取域名 {domainName} 的 ID",
                    ErrorCode = "DOMAIN_NOT_FOUND"
                };
            }

            var subDomain = DnsDomainHelper.ExtractSubDomain(recordName, domainName);

            // 获取所有匹配的 TXT 记录
            var parameters = new Dictionary<string, string>
            {
                ["domain_id"] = domainId,
                ["sub_domain"] = subDomain,
                ["record_type"] = "TXT",
                ["login_token"] = loginToken
            };

            var response = await SendRequest("Record.List", parameters);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.DnsPodApiResponse);
                if (result?.Records != null && result.Records.Count > 0)
                {
                    var deletedCount = 0;
                    foreach (var record in result.Records)
                    {
                        if (record.Id != null)
                        {
                            var recordId = record.Id;
                            var deleteResult = await DeleteRecord(domainId, recordId, loginToken);
                            if (deleteResult)
                            {
                                deletedCount++;
                                _logger.LogInformation("已删除 DNS TXT 记录: {RecordId}", recordId);
                            }
                        }
                    }

                    return new DnsOperationResult
                    {
                        Success = true,
                        Message = $"成功删除 {deletedCount} 条 DNS TXT 记录",
                        Details = $"已删除 {deletedCount} 条记录"
                    };
                }
            }

            return new DnsOperationResult
            {
                Success = true,
                Message = "没有找到匹配的记录或已全部删除"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除所有 DNS TXT 记录时发生错误: {RecordName}", recordName);
            return new DnsOperationResult
            {
                Success = false,
                Message = $"删除 DNS TXT 记录时发生错误: {ex.Message}",
                ErrorCode = "EXCEPTION"
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
            _logger.LogInformation("测试 DNSPod API 连接");

            var secretId = GetSecretId(credentials);
            var secretKey = GetSecretKey(credentials);

            if (string.IsNullOrEmpty(secretId) || string.IsNullOrEmpty(secretKey))
            {
                return new DnsTestResult
                {
                    Success = false,
                    Message = "DNSPod Secret 未提供",
                    ErrorCode = "MISSING_CREDENTIALS"
                };
            }

            var loginToken = $"{secretId},{secretKey}";

            // 尝试获取域名列表来测试连接
            var parameters = new Dictionary<string, string>
            {
                ["login_token"] = loginToken
            };

            var response = await SendRequest("Domain.List", parameters);
            var responseContent = await response.Content.ReadAsStringAsync();

            _logger.LogInformation("DNSPod API 测试响应状态: {StatusCode}, 内容: {Content}", response.StatusCode, responseContent);

            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.DnsPodApiResponse);
                // DNSPod 传统 API 即使业务失败也返回 HTTP 200；成功以 status.code=="1" 为准。
                // 中文响应 message 不含 "success" 字样，不能拿 Contains("success") 判定。
                if (result != null
                    && result.Status.ValueKind == JsonValueKind.Object
                    && result.Status.TryGetProperty("code", out var code)
                    && code.GetRawText().Trim('"') == "1")
                {
                    return new DnsTestResult
                    {
                        Success = true,
                        Message = "DNSPod API 连接测试成功"
                    };
                }
            }

            return new DnsTestResult
            {
                Success = false,
                Message = "DNSPod API 连接测试失败",
                ErrorCode = "CONNECTION_FAILED",
                Details = responseContent
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "测试 DNSPod API 连接时发生错误");
            return new DnsTestResult
            {
                Success = false,
                Message = $"测试连接时发生错误: {ex.Message}",
                ErrorCode = "EXCEPTION"
            };
        }
    }

    #region 私有方法

    private string? GetSecretId(IReadOnlyDictionary<string, object?>? credentials)
    {
        return credentials?.GetValueOrDefault("secretId")?.ToString()
               ?? credentials?.GetValueOrDefault("SecretId")?.ToString()
               ?? credentials?.GetValueOrDefault("secret_id")?.ToString()
               ?? _configuration["DnsProviders:DnsPod:SecretId"];
    }

    private string? GetSecretKey(IReadOnlyDictionary<string, object?>? credentials)
    {
        return credentials?.GetValueOrDefault("secretKey")?.ToString()
               ?? credentials?.GetValueOrDefault("SecretKey")?.ToString()
               ?? credentials?.GetValueOrDefault("secret_key")?.ToString()
               ?? _configuration["DnsProviders:DnsPod:SecretKey"];
    }

    private async Task<string?> GetDomainId(string domain, string loginToken)
    {
        try
        {
            _logger.LogInformation("开始获取域名列表，查找域名: {Domain}", domain);

            var parameters = new Dictionary<string, string>
            {
                ["login_token"] = loginToken
            };

            var response = await SendRequest("Domain.List", parameters);
            var responseContent = await response.Content.ReadAsStringAsync();

            _logger.LogDebug("DNSPod API 响应: {Content}", responseContent);

            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.DnsPodApiResponse);
                if (result?.Domains != null)
                {
                    var targetDomain = result.Domains.FirstOrDefault(d =>
                        d.Name?.Equals(domain, StringComparison.OrdinalIgnoreCase) == true);

                    if (targetDomain?.Id != null)
                    {
                        var domainId = targetDomain.Id;
                        _logger.LogInformation("找到域名 ID: {DomainId} for {Domain}", domainId, domain);

                        // 缓存映射
                        if (!string.IsNullOrEmpty(domainId))
                        {
                            _domainIdToNameMap[domainId] = domain;
                        }

                        return domainId;
                    }
                }
            }

            _logger.LogWarning("未找到域名: {Domain}", domain);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取域名 ID 时发生错误: {Domain}", domain);
            return null;
        }
    }

    private async Task<string?> CreateRecord(string domainId, string subDomain, string recordValue, string loginToken)
    {
        try
        {
            _logger.LogInformation("创建 TXT 记录: 域名ID={DomainId}, 子域名={SubDomain}, 值={RecordValue}",
                domainId, subDomain, recordValue);

            var parameters = new Dictionary<string, string>
            {
                ["domain_id"] = domainId,
                ["sub_domain"] = subDomain,
                ["record_type"] = "TXT",
                ["record_line"] = "默认",
                ["value"] = recordValue,
                ["ttl"] = "600",
                ["login_token"] = loginToken
            };

            var response = await SendRequest("Record.Create", parameters);
            var responseContent = await response.Content.ReadAsStringAsync();

            _logger.LogInformation("DNSPod 创建记录响应: {Content}", responseContent);

            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.DnsPodApiResponse);
                if (result?.Record?.Id != null)
                {
                    var recordId = result.Record.Id;
                    _logger.LogInformation("记录创建成功，ID: {RecordId}", recordId);
                    return recordId;
                }
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建记录时发生错误");
            return null;
        }
    }

    private async Task<string?> GetRecordId(string domainId, string subDomain, string recordValue, string loginToken)
    {
        try
        {
            var parameters = new Dictionary<string, string>
            {
                ["domain_id"] = domainId,
                ["sub_domain"] = subDomain,
                ["record_type"] = "TXT",
                ["login_token"] = loginToken
            };

            var response = await SendRequest("Record.List", parameters);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.DnsPodApiResponse);
                if (result?.Records != null)
                {
                    var targetRecord = result.Records.FirstOrDefault(r =>
                        r.Value?.Equals(recordValue, StringComparison.OrdinalIgnoreCase) == true);

                    if (targetRecord?.Id != null)
                    {
                        return targetRecord.Id;
                    }
                }
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取记录 ID 时发生错误");
            return null;
        }
    }

    private async Task<bool> DeleteRecord(string domainId, string recordId, string loginToken)
    {
        try
        {
            var parameters = new Dictionary<string, string>
            {
                ["domain_id"] = domainId,
                ["record_id"] = recordId,
                ["login_token"] = loginToken
            };

            var response = await SendRequest("Record.Remove", parameters);
            var responseContent = await response.Content.ReadAsStringAsync();

            _logger.LogInformation("DNSPod 删除记录响应: {Content}", responseContent);

            // DNSPod 业务失败也返回 HTTP 200，需以 status.code=="1" 判定成功。
            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.DnsPodApiResponse);
                return result?.Status.ValueKind == JsonValueKind.Object
                       && result.Status.TryGetProperty("code", out var code)
                       && code.GetRawText().Trim('"') == "1";
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除记录时发生错误");
            return false;
        }
    }

    /// <summary>
    /// 发送传统 DNSPod API 请求
    /// 使用 FormUrlEncodedContent 格式
    /// </summary>
    private async Task<HttpResponseMessage> SendRequest(string action, Dictionary<string, string> parameters)
    {
        // 添加格式参数
        if (!parameters.ContainsKey("format"))
        {
            parameters["format"] = "json";
        }

        var content = new FormUrlEncodedContent(parameters);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

        var request = new HttpRequestMessage(HttpMethod.Post, action)
        {
            Content = content
        };
        request.Headers.UserAgent.ParseAdd("DockerPanel-ACME/1.0");

        _logger.LogInformation("DNSPod API 请求: Action={Action}", action);

        var response = await _httpClient.SendAsync(request);
        var responseContent = await response.Content.ReadAsStringAsync();

        _logger.LogInformation("DNSPod API 响应状态: {StatusCode}, 内容: {Content}",
            response.StatusCode, responseContent);

        return response;
    }

    #endregion
}

#region DNSPod API 响应模型

public sealed class DnsPodApiResponse
{
    [JsonPropertyName("status")]
    public JsonElement Status { get; set; }
    [JsonPropertyName("domains")]
    public List<DnsPodDomain>? Domains { get; set; }
    [JsonPropertyName("records")]
    public List<DnsPodRecord>? Records { get; set; }
    [JsonPropertyName("record")]
    public DnsPodRecord? Record { get; set; }
}

public sealed class DnsPodDomain
{
    [JsonPropertyName("id")]
    [JsonConverter(typeof(JsonStringOrNumberConverter))]
    public string? Id { get; set; }
    [JsonPropertyName("name")]
    public string? Name { get; set; }
}

public sealed class DnsPodRecord
{
    [JsonPropertyName("id")]
    [JsonConverter(typeof(JsonStringOrNumberConverter))]
    public string? Id { get; set; }
    [JsonPropertyName("value")]
    public string? Value { get; set; }
}

#endregion
