using System.Text.Json.Serialization;

namespace AcmeForge.Resources;

/// <summary>ACME directory 响应。</summary>
public sealed class AcmeDirectory
{
    [JsonPropertyName("newNonce")]
    public string? NewNonce { get; set; }

    [JsonPropertyName("newAccount")]
    public string? NewAccount { get; set; }

    [JsonPropertyName("newOrder")]
    public string? NewOrder { get; set; }

    [JsonPropertyName("revokeCert")]
    public string? RevokeCert { get; set; }

    [JsonPropertyName("keyChange")]
    public string? KeyChange { get; set; }

    [JsonPropertyName("renewalInfo")]
    public string? RenewalInfo { get; set; }

    [JsonPropertyName("meta")]
    public AcmeDirectoryMeta? Meta { get; set; }
}

public sealed class AcmeDirectoryMeta
{
    [JsonPropertyName("termsOfService")]
    public string? TermsOfService { get; set; }

    [JsonPropertyName("website")]
    public string? Website { get; set; }

    [JsonPropertyName("caaIdentities")]
    public string[]? CaaIdentities { get; set; }

    [JsonPropertyName("externalAccountRequired")]
    public bool? ExternalAccountRequired { get; set; }
}

/// <summary>ACME 账户资源。</summary>
public sealed class AcmeAccount
{
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("contact")]
    public string[]? Contact { get; set; }

    [JsonPropertyName("orders")]
    public string? Orders { get; set; }

    [JsonPropertyName("termsOfServiceAgreed")]
    public bool? TermsOfServiceAgreed { get; set; }
}

/// <summary>ACME 订单资源。</summary>
public sealed class AcmeOrder
{
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("expires")]
    public string? Expires { get; set; }

    [JsonPropertyName("identifiers")]
    public AcmeIdentifier[]? Identifiers { get; set; }

    [JsonPropertyName("notBefore")]
    public string? NotBefore { get; set; }

    [JsonPropertyName("notAfter")]
    public string? NotAfter { get; set; }

    [JsonPropertyName("error")]
    public AcmeProblem? Error { get; set; }

    [JsonPropertyName("authorizations")]
    public string[]? Authorizations { get; set; }

    [JsonPropertyName("finalize")]
    public string? Finalize { get; set; }

    [JsonPropertyName("certificate")]
    public string? Certificate { get; set; }
}

/// <summary>ACME 标识符。</summary>
public sealed class AcmeIdentifier
{
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("value")]
    public string? Value { get; set; }
}

/// <summary>ACME 授权资源。</summary>
public sealed class AcmeAuthorization
{
    [JsonPropertyName("identifier")]
    public AcmeIdentifier? Identifier { get; set; }

    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("expires")]
    public string? Expires { get; set; }

    [JsonPropertyName("challenges")]
    public AcmeChallenge[]? Challenges { get; set; }

    [JsonPropertyName("wildcard")]
    public bool? Wildcard { get; set; }
}

/// <summary>ACME 挑战资源。</summary>
public sealed class AcmeChallenge
{
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("url")]
    public string? Url { get; set; }

    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("token")]
    public string? Token { get; set; }

    [JsonPropertyName("validated")]
    public string? Validated { get; set; }

    [JsonPropertyName("error")]
    public AcmeProblem? Error { get; set; }
}

/// <summary>RFC 7807 problem details（ACME 错误）。</summary>
public sealed class AcmeProblem
{
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("detail")]
    public string? Detail { get; set; }

    [JsonPropertyName("title")]
    public string? Title { get; set; }

    [JsonPropertyName("status")]
    public int? Status { get; set; }

    [JsonPropertyName("identifier")]
    public AcmeIdentifier? Identifier { get; set; }

    [JsonPropertyName("subproblems")]
    public AcmeProblem[]? Subproblems { get; set; }
}

/// <summary>ACME 问题类型常量。</summary>
public static class AcmeErrorTypes
{
    public const string BadNonce = "urn:ietf:params:acme:error:badNonce";
    public const string BadPublicKey = "urn:ietf:params:acme:error:badPublicKey";
    public const string BadRevocationReason = "urn:ietf:params:acme:error:badRevocationReason";
    public const string BadSignatureAlgorithm = "urn:ietf:params:acme:error:badSignatureAlgorithm";
    public const string Malformed = "urn:ietf:params:acme:error:malformed";
    public const string AccountDoesNotExist = "urn:ietf:params:acme:error:accountDoesNotExist";
    public const string AlreadyRevoked = "urn:ietf:params:acme:error:alreadyRevoked";
    public const string RateLimited = "urn:ietf:params:acme:error:rateLimited";
    public const string Unauthorized = "urn:ietf:params:acme:error:unauthorized";
    public const string InvalidContact = "urn:ietf:params:acme:error:invalidContact";
    public const string UserActionRequired = "urn:ietf:params:acme:error:userActionRequired";
    public const string ExternalAccountRequired = "urn:ietf:params:acme:error:externalAccountRequired";
}

/// <summary>RFC 5280 吊销原因码。</summary>
public enum AcmeRevocationReason
{
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}
