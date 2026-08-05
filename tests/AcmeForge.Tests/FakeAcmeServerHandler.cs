using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AcmeForge.Tests;

/// <summary>
/// 内存假 ACME 服务器：校验 JWS（nonce/url/签名），按路径返回资源。
/// 独立实现 RFC 7515 签名验证（不经 AcmeKey），用于端到端测试。
/// </summary>
internal sealed class FakeAcmeServerHandler : HttpMessageHandler
{
    public const string BaseUrl = "https://acme.test";
    public const string DirectoryUrl = BaseUrl + "/directory";
    public const string AccountUrl = BaseUrl + "/acct/1";

    public readonly List<string> PostPaths = new();
    public int NonceHeadCalls;
    public bool RejectFirstPostWithBadNonce;
    public bool FailNextPost;
    public bool RequireExternalAccountBinding;

    /// <summary>每次访问 /order/1 依次返回的订单状态（测试状态流转用），默认 null = 固定 pending。</summary>
    public List<string>? OrderStatusPollSequence;

    /// <summary>每次访问 /challenge/1 依次返回的挑战状态（测试状态流转用），默认 null = 固定 valid。</summary>
    public List<string>? ChallengeStatusPollSequence;

    public string? LastProtectedHeader;
    public string? LastPayload;
    public string? LastSignature;

    private readonly object _gate = new();
    private readonly HashSet<string> _issuedNonces = new();
    private readonly Dictionary<string, string> _jwkByKid = new();
    private int _nonceSeq;
    private bool _firstPostHandled;
    private int _orderPollIndex;
    private int _challengePollIndex;

    private const string DirectoryJson = """
        {
          "newNonce": "https://acme.test/new-nonce",
          "newAccount": "https://acme.test/new-account",
          "newOrder": "https://acme.test/new-order",
          "revokeCert": "https://acme.test/revoke-cert",
          "keyChange": "https://acme.test/key-change",
          "renewalInfo": "https://acme.test/renewal-info",
          "meta": {
            "termsOfService": "https://acme.test/terms",
            "website": "https://acme.test/",
            "caaIdentities": ["acme.test"],
            "externalAccountRequired": false
          }
        }
        """;

    private const string AccountJson = """
        {"status":"valid","contact":["mailto:admin@example.com"],"orders":"https://acme.test/orders/1","termsOfServiceAgreed":true}
        """;

    private const string OrderJson = """
        {
          "status": "pending",
          "expires": "2026-01-01T00:00:00Z",
          "identifiers": [
            {"type":"dns","value":"example.com"},
            {"type":"dns","value":"www.example.com"}
          ],
          "authorizations": ["https://acme.test/authz/1","https://acme.test/authz/2"],
          "finalize": "https://acme.test/finalize/1"
        }
        """;

    private const string AuthorizationJson = """
        {
          "identifier": {"type":"dns","value":"example.com"},
          "status": "pending",
          "expires": "2026-01-01T00:00:00Z",
          "wildcard": false,
          "challenges": [
            {"type":"dns-01","url":"https://acme.test/challenge/1","status":"pending","token":"tok_abc"}
          ]
        }
        """;

    private const string ChallengeJson = """
        {"type":"dns-01","url":"https://acme.test/challenge/1","status":"valid","token":"tok_abc","validated":"2026-01-01T00:00:00Z"}
        """;

    private const string FinalizedOrderJson = """
        {"status":"processing","finalize":"https://acme.test/finalize/1","certificate":"https://acme.test/cert/1"}
        """;

    public const string CertificatePem = """
        -----BEGIN CERTIFICATE-----
        MIIB8TCCAZegAwIBAgIJALdHZkM3wPMoMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNV
        BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
        aWRnaXRzIFB0eSBMdGQxEDAOBgNVBAMMB2V4YW1wbGUwHhcNMTYwNDI0MTYwMDAw
        WhcNMTYwNTI0MTYwMDAwWjBXMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1T
        dGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRAwDgYDVQQD
        DAdleGFtcGxlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/IKMc2mh2xAhkPKg
        ARQcNLQ9b7u0XwD3XyZ7h9mzK8iBd0kzFnZC4Xf0T8u3EqD5QlQjH9kNbZ5KjY5t
        Y1NuOjANBgkqhkiG9w0BAQsFAAOCAQEAaZxLm1ZQr9CXvGQnXf9xqCJGZ9hU0G7
        dHdLm3u3X1cQb0vKzY5mD0zYvJQvQkzY1JhWc5zLpXZzY2hO9k1nBvXj0gW2xR
        tQ==
        -----END CERTIFICATE-----
        """;

    public FakeAcmeServerHandler()
    {
        _issuedNonces.Add("initial-nonce");
    }

    private string IssueNonce()
    {
        lock (_gate)
        {
            var nonce = $"nonce-{++_nonceSeq}";
            _issuedNonces.Add(nonce);
            return nonce;
        }
    }

    private bool ConsumeNonce(string? nonce)
    {
        lock (_gate)
        {
            return nonce is not null && _issuedNonces.Remove(nonce);
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath;

        if (request.Method == HttpMethod.Get && path == "/directory")
        {
            return Json(200, DirectoryJson, nonce: IssueNonce());
        }

        if (request.Method == HttpMethod.Head && path == "/new-nonce")
        {
            NonceHeadCalls++;
            return NonceOnly(IssueNonce());
        }

        if (request.Method != HttpMethod.Post)
        {
            return Json(405, "{\"detail\":\"method not allowed\"}");
        }

        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        PostPaths.Add(path);

        if (FailNextPost)
        {
            FailNextPost = false;
            return Json(403, "{\"type\":\"urn:ietf:params:acme:error:unauthorized\",\"detail\":\"account not authorized\",\"status\":403}", nonce: IssueNonce());
        }

        if (RejectFirstPostWithBadNonce && !_firstPostHandled)
        {
            _firstPostHandled = true;
            return Json(400, "{\"type\":\"urn:ietf:params:acme:error:badNonce\",\"detail\":\"bad nonce\"}", nonce: IssueNonce());
        }

        return RoutePost(path, request.RequestUri!.AbsoluteUri, body);
    }

    private HttpResponseMessage RoutePost(string path, string requestUrl, string body)
    {
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        var protectedB64 = root.GetProperty("protected").GetString()!;
        var payload = root.GetProperty("payload").GetString()!;
        var signature = root.GetProperty("signature").GetString()!;

        var protectedJson = Encoding.UTF8.GetString(B64UrlDecode(protectedB64));
        using var headerDoc = JsonDocument.Parse(protectedJson);
        var header = headerDoc.RootElement;

        var nonce = header.GetProperty("nonce").GetString();
        var url = header.GetProperty("url").GetString();
        if (url != requestUrl)
        {
            throw new InvalidOperationException($"JWS url '{url}' != request url '{requestUrl}'");
        }

        if (!ConsumeNonce(nonce))
        {
            return Json(400, "{\"type\":\"urn:ietf:params:acme:error:badNonce\",\"detail\":\"nonce already used or invalid\"}", nonce: IssueNonce());
        }

        var signingInput = Encoding.ASCII.GetBytes(protectedB64 + "." + payload);

        if (header.TryGetProperty("jwk", out var jwk))
        {
            VerifyJwsSignature(signingInput, signature, jwk);
            if (path == "/new-account")
            {
                _jwkByKid[AccountUrl] = jwk.GetRawText();
            }
        }
        else if (header.TryGetProperty("kid", out var kid))
        {
            if (!_jwkByKid.TryGetValue(kid.GetString()!, out var registeredJwk))
            {
                throw new InvalidOperationException($"unknown kid '{kid.GetString()}'");
            }

            using var registeredDoc = JsonDocument.Parse(registeredJwk);
            VerifyJwsSignature(signingInput, signature, registeredDoc.RootElement);
        }
        else
        {
            throw new InvalidOperationException("JWS header missing jwk and kid");
        }

        LastProtectedHeader = protectedJson;
        LastPayload = payload;
        LastSignature = signature;

        return path switch
        {
            "/new-account" => RequireExternalAccountBinding
                ? Json(400, "{\"type\":\"urn:ietf:params:acme:error:externalAccountRequired\",\"detail\":\"No External Account Binding present\"}", nonce: IssueNonce())
                : Json(201, AccountJson, location: AccountUrl, nonce: IssueNonce()),
            "/new-order" => Json(201, OrderJson, location: BaseUrl + "/order/1", nonce: IssueNonce()),
            "/finalize/1" => Json(200, FinalizedOrderJson, nonce: IssueNonce()),
            "/challenge/1" => Json(200, NextChallengeJson(), nonce: IssueNonce()),
            "/authz/1" => Json(200, AuthorizationJson, nonce: IssueNonce()),
            "/order/1" => Json(200, NextOrderJson(), nonce: IssueNonce()),
            "/acct/1" => Json(200, AccountJson, nonce: IssueNonce()),
            "/cert/1" => Json(200, CertificatePem, nonce: IssueNonce(), contentType: "application/pem-certificate-chain"),
            "/revoke-cert" => Json(200, "", nonce: IssueNonce()),
            "/new-nonce" => Json(204, "", nonce: IssueNonce()),
            _ => Json(404, "{\"type\":\"urn:ietf:params:acme:error:malformed\",\"detail\":\"not found\"}", nonce: IssueNonce()),
        };
    }

    /// <summary>按状态序列返回订单 JSON，未配置序列时固定返回 pending 订单。</summary>
    private string NextOrderJson()
    {
        if (OrderStatusPollSequence is null)
        {
            return OrderJson;
        }

        lock (_gate)
        {
            var status = OrderStatusPollSequence[Math.Min(_orderPollIndex++, OrderStatusPollSequence.Count - 1)];
            return BuildOrderJson(status);
        }
    }

    /// <summary>按状态序列返回挑战 JSON，未配置序列时固定返回 valid 挑战。</summary>
    private string NextChallengeJson()
    {
        if (ChallengeStatusPollSequence is null)
        {
            return ChallengeJson;
        }

        lock (_gate)
        {
            var status = ChallengeStatusPollSequence[Math.Min(_challengePollIndex++, ChallengeStatusPollSequence.Count - 1)];
            return $@"{{""type"":""dns-01"",""url"":""{BaseUrl}/challenge/1"",""status"":""{status}"",""token"":""tok_abc""}}";
        }
    }

    /// <summary>按订单状态构建订单 JSON（ready/processing/valid 附 finalize 或 certificate 端点）。</summary>
    private static string BuildOrderJson(string status)
    {
        var finalize = status == "ready" || status == "processing"
            ? $@",""finalize"":""{BaseUrl}/finalize/1"""
            : string.Empty;
        var certificate = status == "valid"
            ? $@",""certificate"":""{BaseUrl}/cert/1"""
            : string.Empty;
        return $@"{{""status"":""{status}"",""expires"":""2026-01-01T00:00:00Z"",""identifiers"":[{{""type"":""dns"",""value"":""example.com""}}],""authorizations"":[""{BaseUrl}/authz/1""]{finalize}{certificate}}}";
    }

    private static void VerifyJwsSignature(byte[] signingInput, string signatureB64, JsonElement jwk)
    {
        var kty = jwk.GetProperty("kty").GetString();
        var signature = B64UrlDecode(signatureB64);

        switch (kty)
        {
            case "EC":
            {
                var crv = jwk.GetProperty("crv").GetString();
                var x = B64UrlDecode(jwk.GetProperty("x").GetString()!);
                var y = B64UrlDecode(jwk.GetProperty("y").GetString()!);
                var expectedLength = crv == "P-384" ? 48 : 32;
                var hash = crv == "P-384" ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
                var curve = crv == "P-384" ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP256;

                using var ecdsa = ECDsa.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = x, Y = y } });

                if (signature.Length == expectedLength * 2)
                {
                    if (ecdsa.VerifyData(signingInput, signature, hash))
                    {
                        return;
                    }
                }

                var der = JoseSignatureToDer(signature, expectedLength);
                if (ecdsa.VerifyData(signingInput, der, hash))
                {
                    return;
                }

                throw new InvalidOperationException("EC JWS signature invalid");
            }
            case "RSA":
            {
                var n = B64UrlDecode(jwk.GetProperty("n").GetString()!);
                var e = B64UrlDecode(jwk.GetProperty("e").GetString()!);
                using var rsa = RSA.Create(new RSAParameters { Modulus = n, Exponent = e });
                if (!rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                {
                    throw new InvalidOperationException("RSA JWS signature invalid");
                }

                return;
            }
            default:
                throw new InvalidOperationException($"unsupported kty '{kty}'");
        }
    }

    private static byte[] JoseSignatureToDer(byte[] jose, int expectedLength)
    {
        var r = jose.AsSpan(0, expectedLength).TrimStart((byte)0).ToArray();
        var s = jose.AsSpan(expectedLength, expectedLength).TrimStart((byte)0).ToArray();
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteInteger(r);
        writer.WriteInteger(s);
        writer.PopSequence();
        return writer.Encode();
    }

    private static byte[] B64UrlDecode(string value)
    {
        value = value.Replace('-', '+').Replace('_', '/');
        while (value.Length % 4 != 0)
        {
            value += "=";
        }

        return Convert.FromBase64String(value);
    }

    private static HttpResponseMessage Json(int status, string json, string? location = null, string? nonce = null, string? contentType = null)
    {
        var response = new HttpResponseMessage((HttpStatusCode)status);
        if (!string.IsNullOrEmpty(json))
        {
            response.Content = new StringContent(json, Encoding.UTF8, contentType ?? "application/json");
        }

        if (location is not null)
        {
            response.Headers.Location = new Uri(location);
        }

        if (nonce is not null)
        {
            response.Headers.TryAddWithoutValidation("Replay-Nonce", nonce);
        }

        return response;
    }

    private static HttpResponseMessage NonceOnly(string nonce)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK);
        response.Headers.TryAddWithoutValidation("Replay-Nonce", nonce);
        return response;
    }
}
