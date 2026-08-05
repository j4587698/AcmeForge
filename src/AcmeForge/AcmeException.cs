namespace AcmeForge;

/// <summary>ACME 协议错误（RFC 7807 problem details）。</summary>
public sealed class AcmeException : Exception
{
    public AcmeException(string message, string? errorType = null, string? detail = null, int? httpStatus = null, Exception? innerException = null)
        : base(message, innerException)
    {
        ErrorType = errorType;
        Detail = detail;
        HttpStatus = httpStatus;
    }

    /// <summary>ACME 错误类型（如 urn:ietf:params:acme:error:badNonce）。</summary>
    public string? ErrorType { get; }

    /// <summary>ACME 错误详情。</summary>
    public string? Detail { get; }

    /// <summary>HTTP 状态码。</summary>
    public int? HttpStatus { get; }
}

/// <summary>External Account Binding 凭据（ZeroSSL、Google Trust Services、SSL.com 等要求）。</summary>
public sealed record EabCredentials(string KeyId, string HmacKey);
