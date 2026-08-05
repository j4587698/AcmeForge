using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AcmeForge.Dns;

/// <summary>
/// Azure DNS API 提供商实现
/// </summary>
public class AzureDnsProvider : IDnsProvider
{
    private readonly ILogger<AzureDnsProvider> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;
    private string? _cachedAccessToken;
    private DateTime _tokenExpiresAt;

    public AzureDnsProvider(
        ILogger<AzureDnsProvider> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
    {
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _httpClient = _httpClientFactory.CreateClient("AzureDns");
    }

    public string Name => "azure";
    public string DisplayName => "Azure DNS";
    public bool RequiresCredentials => true;

    /// <summary>
    /// 创建 DNS TXT 记录
    /// </summary>
    public async Task<DnsOperationResult> CreateTxtRecordAsync(string domain, string recordName, string recordValue, IReadOnlyDictionary<string, object?>? credentials)
    {
        try
        {
            _logger.LogInformation("创建 Azure DNS TXT 记录: {RecordName} = {RecordValue}", recordName, recordValue);

            var clientId = GetClientId(credentials);
            var clientSecret = GetClientSecret(credentials);
            var tenantId = GetTenantId(credentials);
            var subscriptionId = GetSubscriptionId(credentials);
            var resourceGroup = GetResourceGroup(credentials);

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) ||
                string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(subscriptionId) ||
                string.IsNullOrEmpty(resourceGroup))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = "Azure DNS 配置不完整，请提供 Client ID、Client Secret、Tenant ID、Subscription ID 和 Resource Group",
                    ErrorCode = "MISSING_CREDENTIALS"
                };
            }

            // 获取访问令牌
            var accessToken = await GetAccessTokenAsync(clientId, clientSecret, tenantId);
            if (string.IsNullOrEmpty(accessToken))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = "无法获取 Azure 访问令牌",
                    ErrorCode = "AUTH_FAILED"
                };
            }

            // 获取 DNS Zone 名称
            var zoneName = DnsDomainHelper.ExtractRootDomain(domain);

            // 构建记录集名称
            var relativeRecordName = GetRelativeRecordName(recordName, zoneName);

            // 构建请求 URL
            var url = $"https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Network/dnszones/{zoneName}/TXT/{relativeRecordName}?api-version=2018-05-01";

            // 构建请求体
            var requestBody = new AzureDnsRecordSetRequest
            {
                Properties = new AzureDnsRecordSetProperties
                {
                    TTL = 120,
                    TXTRecords =
                    {
                        new AzureTxtRecordValue { Value = { recordValue } }
                    }
                }
            };

            var json = JsonSerializer.Serialize(requestBody, DnsJsonContext.Instance.AzureDnsRecordSetRequest);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            // 发送请求 (使用 PUT 创建或更新)
            using var request = new HttpRequestMessage(HttpMethod.Put, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            request.Content = content;

            var response = await _httpClient.SendAsync(request);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("创建 Azure DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"创建 DNS 记录失败: {response.StatusCode}",
                    ErrorCode = "CREATE_FAILED",
                    Details = responseContent
                };
            }

            _logger.LogInformation("Azure DNS TXT 记录创建成功: {RecordName}", recordName);
            return new DnsOperationResult
            {
                Success = true,
                Message = "DNS 记录创建成功",
                Details = $"Zone: {zoneName}, Record: {relativeRecordName}"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "创建 Azure DNS 记录异常: {RecordName}", recordName);
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
            _logger.LogInformation("删除 Azure DNS TXT 记录: {RecordName}", recordName);

            var clientId = GetClientId(credentials);
            var clientSecret = GetClientSecret(credentials);
            var tenantId = GetTenantId(credentials);
            var subscriptionId = GetSubscriptionId(credentials);
            var resourceGroup = GetResourceGroup(credentials);

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) ||
                string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(subscriptionId) ||
                string.IsNullOrEmpty(resourceGroup))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = "Azure DNS 配置不完整",
                    ErrorCode = "MISSING_CREDENTIALS"
                };
            }

            // 获取访问令牌
            var accessToken = await GetAccessTokenAsync(clientId, clientSecret, tenantId);
            if (string.IsNullOrEmpty(accessToken))
            {
                return new DnsOperationResult
                {
                    Success = false,
                    Message = "无法获取 Azure 访问令牌",
                    ErrorCode = "AUTH_FAILED"
                };
            }

            // 获取 DNS Zone 名称
            var zoneName = DnsDomainHelper.ExtractRootDomain(domain);

            // 构建记录集名称
            var relativeRecordName = GetRelativeRecordName(recordName, zoneName);

            // 构建请求 URL
            var url = $"https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Network/dnszones/{zoneName}/TXT/{relativeRecordName}?api-version=2018-05-01";

            // 发送删除请求
            using var request = new HttpRequestMessage(HttpMethod.Delete, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await _httpClient.SendAsync(request);
            var responseContent = await response.Content.ReadAsStringAsync();

            // Azure 返回 204 表示成功删除，404 表示不存在
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                _logger.LogWarning("Azure DNS 记录不存在: {RecordName}", recordName);
                return new DnsOperationResult
                {
                    Success = true,
                    Message = "记录不存在，无需删除"
                };
            }

            if (!response.IsSuccessStatusCode && response.StatusCode != System.Net.HttpStatusCode.NoContent)
            {
                _logger.LogError("删除 Azure DNS 记录失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsOperationResult
                {
                    Success = false,
                    Message = $"删除 DNS 记录失败: {response.StatusCode}",
                    ErrorCode = "DELETE_FAILED",
                    Details = responseContent
                };
            }

            _logger.LogInformation("Azure DNS TXT 记录删除成功: {RecordName}", recordName);
            return new DnsOperationResult
            {
                Success = true,
                Message = "DNS 记录删除成功"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "删除 Azure DNS 记录异常: {RecordName}", recordName);
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
            _logger.LogInformation("测试 Azure DNS 连接");

            var clientId = GetClientId(credentials);
            var clientSecret = GetClientSecret(credentials);
            var tenantId = GetTenantId(credentials);
            var subscriptionId = GetSubscriptionId(credentials);
            var resourceGroup = GetResourceGroup(credentials);

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) ||
                string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(subscriptionId))
            {
                return new DnsTestResult
                {
                    Success = false,
                    Message = "Azure DNS 配置不完整",
                    ErrorCode = "MISSING_CREDENTIALS"
                };
            }

            // 获取访问令牌
            var accessToken = await GetAccessTokenAsync(clientId, clientSecret, tenantId);
            if (string.IsNullOrEmpty(accessToken))
            {
                return new DnsTestResult
                {
                    Success = false,
                    Message = "无法获取 Azure 访问令牌",
                    ErrorCode = "AUTH_FAILED"
                };
            }

            // 测试列出 DNS Zones
            var url = $"https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Network/dnszones?api-version=2018-05-01";

            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await _httpClient.SendAsync(request);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Azure DNS API 认证失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return new DnsTestResult
                {
                    Success = false,
                    Message = $"API 认证失败: {response.StatusCode}",
                    ErrorCode = "AUTH_FAILED",
                    Details = responseContent
                };
            }

            // 解析响应
            var zonesResult = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.AzureDnsZonesResponse);
            var zoneCount = zonesResult?.Value?.Count ?? 0;

            return new DnsTestResult
            {
                Success = true,
                Message = "Azure DNS API 连接测试成功",
                Details = $"找到 {zoneCount} 个 DNS Zone"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "测试 Azure DNS 连接异常");
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
            _logger.LogInformation("Azure DNS: 删除所有匹配的 DNS TXT 记录: {RecordName}", recordName);

            // Azure DNS 使用记录集，一个记录集可以包含多个值
            // 直接删除整个记录集即可
            return await DeleteTxtRecordAsync(domain, recordName, "", credentials);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Azure DNS 删除所有 DNS TXT 记录时发生错误: {RecordName}", recordName);
            return new DnsOperationResult
            {
                Success = false,
                Message = $"删除 DNS TXT 记录时发生错误: {ex.Message}",
                ErrorCode = "EXCEPTION"
            };
        }
    }

    #region 私有方法

    private string? GetClientId(IReadOnlyDictionary<string, object?>? credentials)
    {
        return credentials?.GetValueOrDefault("clientId")?.ToString()
               ?? credentials?.GetValueOrDefault("client_id")?.ToString()
               ?? _configuration["DnsProviders:Azure:ClientId"];
    }

    private string? GetClientSecret(IReadOnlyDictionary<string, object?>? credentials)
    {
        return credentials?.GetValueOrDefault("clientSecret")?.ToString()
               ?? credentials?.GetValueOrDefault("client_secret")?.ToString()
               ?? _configuration["DnsProviders:Azure:ClientSecret"];
    }

    private string? GetTenantId(IReadOnlyDictionary<string, object?>? credentials)
    {
        return credentials?.GetValueOrDefault("tenantId")?.ToString()
               ?? credentials?.GetValueOrDefault("tenant_id")?.ToString()
               ?? _configuration["DnsProviders:Azure:TenantId"];
    }

    private string? GetSubscriptionId(IReadOnlyDictionary<string, object?>? credentials)
    {
        return credentials?.GetValueOrDefault("subscriptionId")?.ToString()
               ?? credentials?.GetValueOrDefault("subscription_id")?.ToString()
               ?? _configuration["DnsProviders:Azure:SubscriptionId"];
    }

    private string? GetResourceGroup(IReadOnlyDictionary<string, object?>? credentials)
    {
        return credentials?.GetValueOrDefault("resourceGroup")?.ToString()
               ?? credentials?.GetValueOrDefault("resource_group")?.ToString()
               ?? _configuration["DnsProviders:Azure:ResourceGroup"];
    }

    private async Task<string?> GetAccessTokenAsync(string clientId, string clientSecret, string tenantId)
    {
        // 检查缓存的令牌是否仍然有效
        if (!string.IsNullOrEmpty(_cachedAccessToken) && DateTime.UtcNow < _tokenExpiresAt.AddMinutes(-5))
        {
            return _cachedAccessToken;
        }

        try
        {
            var tokenUrl = $"https://login.microsoftonline.com/{tenantId}/oauth2/token";

            var tokenRequest = new List<KeyValuePair<string, string>>
            {
                new("grant_type", "client_credentials"),
                new("client_id", clientId),
                new("client_secret", clientSecret),
                new("resource", "https://management.azure.com/")
            };

            using var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl);
            request.Content = new FormUrlEncodedContent(tokenRequest);

            var response = await _httpClient.SendAsync(request);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("获取 Azure 访问令牌失败: {StatusCode} - {Content}", response.StatusCode, responseContent);
                return null;
            }

            var tokenResult = JsonSerializer.Deserialize(responseContent, DnsJsonContext.Instance.AzureTokenResponse);
            if (tokenResult == null || string.IsNullOrEmpty(tokenResult.AccessToken))
            {
                _logger.LogError("Azure 令牌响应为空");
                return null;
            }

            // 缓存令牌
            _cachedAccessToken = tokenResult.AccessToken;
            _tokenExpiresAt = DateTime.UtcNow.AddSeconds(tokenResult.ExpiresIn);

            return _cachedAccessToken;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取 Azure 访问令牌异常");
            return null;
        }
    }

    private string GetRelativeRecordName(string recordName, string zoneName)
    {
        // 移除域名后缀，获取相对记录名
        var zoneWithDot = zoneName.EndsWith(".") ? zoneName : zoneName + ".";
        if (recordName.EndsWith(zoneWithDot, StringComparison.OrdinalIgnoreCase))
        {
            return recordName[..^zoneWithDot.Length];
        }
        if (recordName.Equals(zoneName, StringComparison.OrdinalIgnoreCase) ||
            recordName.Equals(zoneWithDot, StringComparison.OrdinalIgnoreCase))
        {
            return "@";
        }
        return recordName;
    }

    #endregion
}

#region Azure API 响应模型

public sealed class AzureTokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = string.Empty;
}

public sealed class AzureDnsZonesResponse
{
    [JsonPropertyName("value")]
    public List<AzureDnsZone>? Value { get; set; }
}

public sealed class AzureDnsZone
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("location")]
    public string Location { get; set; } = string.Empty;
}

public sealed class AzureDnsRecordSetRequest
{
    [JsonPropertyName("properties")]
    public AzureDnsRecordSetProperties Properties { get; set; } = new();
}

public sealed class AzureDnsRecordSetProperties
{
    [JsonPropertyName("TTL")]
    public int TTL { get; set; }

    [JsonPropertyName("TXTRecords")]
    public List<AzureTxtRecordValue> TXTRecords { get; set; } = new();
}

public sealed class AzureTxtRecordValue
{
    [JsonPropertyName("value")]
    public List<string> Value { get; set; } = new();
}

#endregion
