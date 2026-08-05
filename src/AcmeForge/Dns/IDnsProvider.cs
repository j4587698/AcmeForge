namespace AcmeForge.Dns;

/// <summary>DNS 提供商接口。</summary>
public interface IDnsProvider
{
    /// <summary>提供商标识（小写，如 "cloudflare"）。</summary>
    string Name { get; }

    /// <summary>显示名称。</summary>
    string DisplayName { get; }

    /// <summary>是否需要凭据。</summary>
    bool RequiresCredentials { get; }

    /// <summary>创建 DNS TXT 记录。</summary>
    Task<DnsOperationResult> CreateTxtRecordAsync(
        string domain,
        string recordName,
        string recordValue,
        IReadOnlyDictionary<string, object?>? credentials);

    /// <summary>删除 DNS TXT 记录。</summary>
    Task<DnsOperationResult> DeleteTxtRecordAsync(
        string domain,
        string recordName,
        string recordValue,
        IReadOnlyDictionary<string, object?>? credentials);

    /// <summary>测试连接。</summary>
    Task<DnsTestResult> TestConnectionAsync(IReadOnlyDictionary<string, object?>? credentials);

    /// <summary>删除所有匹配名称的 DNS TXT 记录。</summary>
    Task<DnsOperationResult> DeleteAllTxtRecordsByNameAsync(
        string domain,
        string recordName,
        IReadOnlyDictionary<string, object?>? credentials);
}

/// <summary>DNS 操作结果。</summary>
public sealed class DnsOperationResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string ErrorCode { get; set; } = string.Empty;
    public string? RecordId { get; set; }
    public string? Details { get; set; }
    public DateTime OperatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>DNS 连接测试结果。</summary>
public sealed class DnsTestResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string ErrorCode { get; set; } = string.Empty;
    public string? Details { get; set; }
    public DateTime TestedAt { get; set; } = DateTime.UtcNow;
}
