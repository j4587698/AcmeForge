using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using AcmeForge;
using AcmeForge.Resources;

namespace AcmeForge.Tests;

public class AcmeClientTests
{
    private static (AcmeClient Client, FakeAcmeServerHandler Server) CreateClient(AcmeKeyAlgorithm algorithm = AcmeKeyAlgorithm.ES256)
    {
        var server = new FakeAcmeServerHandler();
        var http = new HttpClient(server);
        var key = AcmeKey.Generate(algorithm);
        var client = new AcmeClient(http, new Uri(FakeAcmeServerHandler.DirectoryUrl), key);
        return (client, server);
    }

    private static async Task<(AcmeClient Client, FakeAcmeServerHandler Server)> CreateRegisteredClient()
    {
        var (client, server) = CreateClient();
        await client.NewAccountAsync(new[] { "mailto:admin@example.com" }, true);
        return (client, server);
    }

    [Fact]
    public async Task GetDirectoryAsync_ParsesEndpoints()
    {
        var (client, _) = CreateClient();
        using (client)
        {
            var directory = await client.GetDirectoryAsync();
            Assert.Equal("https://acme.test/new-nonce", directory.NewNonce);
            Assert.Equal("https://acme.test/new-account", directory.NewAccount);
            Assert.Equal("https://acme.test/new-order", directory.NewOrder);
            Assert.Equal("https://acme.test/revoke-cert", directory.RevokeCert);
            Assert.Equal("https://acme.test/key-change", directory.KeyChange);
            Assert.Equal("https://acme.test/renewal-info", directory.RenewalInfo);
            Assert.NotNull(directory.Meta);
            Assert.Equal("https://acme.test/terms", directory.Meta!.TermsOfService);
            Assert.False(directory.Meta.ExternalAccountRequired);
        }
    }

    [Fact]
    public async Task NewAccountAsync_RegistersAndCapturesKid()
    {
        var (client, server) = CreateClient();
        using (client)
        {
            var account = await client.NewAccountAsync(
                new[] { "mailto:admin@example.com" },
                termsOfServiceAgreed: true);

            Assert.Equal("valid", account.Status);
            Assert.Equal("https://acme.test/acct/1", client.Kid);
            Assert.Contains("/new-account", server.PostPaths);
            Assert.NotNull(server.LastProtectedHeader);
        }
    }

    [Fact]
    public async Task NewAccountAsync_Eab_IncludesExternalAccountBinding()
    {
        var (client, server) = CreateClient();
        using (client)
        {
            var eab = new EabCredentials(
                KeyId: "kid-123",
                HmacKey: Convert.ToBase64String(new byte[32]));

            await client.NewAccountAsync(Array.Empty<string>(), termsOfServiceAgreed: true, eab);

            var payload = Base64UrlText.Decode(server.LastPayload!);
            using var doc = JsonDocument.Parse(payload);
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("externalAccountBinding", out var eabElement));
            Assert.True(eabElement.TryGetProperty("protected", out _));
            Assert.True(eabElement.TryGetProperty("payload", out _));
            Assert.True(eabElement.TryGetProperty("signature", out _));
        }
    }

    [Fact]
    public async Task NewAccountAsync_ExternalAccountRequired_HintsEab()
    {
        var (client, server) = CreateClient();
        server.RequireExternalAccountBinding = true;
        using (client)
        {
            var ex = await Assert.ThrowsAsync<AcmeException>(() =>
                client.NewAccountAsync(["mailto:admin@example.com"], termsOfServiceAgreed: true));

            Assert.Equal(AcmeErrorTypes.ExternalAccountRequired, ex.ErrorType);
            Assert.Contains("EabCredentials", ex.Message);
        }
    }

    [Fact]
    public async Task BadNonce_IsRetried_AndSucceeds()
    {
        var (client, server) = CreateClient();
        server.RejectFirstPostWithBadNonce = true;
        using (client)
        {
            var account = await client.NewAccountAsync(new[] { "mailto:admin@example.com" }, true);

            Assert.Equal("valid", account.Status);
            Assert.NotNull(client.Kid);
            // 首次 badNonce 后必须经 HEAD 重取 nonce 再重试
            Assert.True(server.NonceHeadCalls >= 1);
            // new-account 被请求了两次
            Assert.Equal(2, server.PostPaths.Count(p => p == "/new-account"));
        }
    }

    [Fact]
    public async Task Nonce_FromDirectory_IsReused_WithoutHeadCalls()
    {
        var (client, server) = CreateClient();
        using (client)
        {
            await client.NewAccountAsync(new[] { "mailto:admin@example.com" }, true);
            await client.NewOrderAsync(new[] { "example.com" });

            // directory GET 已捕获 nonce，随后每个响应都带新 nonce，无需 HEAD new-nonce
            Assert.Equal(0, server.NonceHeadCalls);
        }
    }

    [Fact]
    public async Task NewOrderAsync_ParsesOrder_AndSetsLastOrderUrl()
    {
        var (client, server) = await CreateRegisteredClient();
        using (client)
        {
            var order = await client.NewOrderAsync(new[] { "example.com", "www.example.com" });

            Assert.Equal("pending", order.Status);
            Assert.Equal(2, order.Identifiers!.Length);
            Assert.Equal("dns", order.Identifiers[0].Type);
            Assert.Equal("example.com", order.Identifiers[0].Value);
            Assert.Equal("https://acme.test/finalize/1", order.Finalize);
            Assert.Equal("https://acme.test/order/1", client.LastOrderUrl);

            // 验证请求 payload 含正确的 identifiers
            var payload = Base64UrlText.Decode(server.LastPayload!);
            using var doc = JsonDocument.Parse(payload);
            Assert.Equal("example.com", doc.RootElement.GetProperty("identifiers")[0].GetProperty("value").GetString());
        }
    }

    [Fact]
    public async Task GetOrderAuthorizationChallenge_ReturnResources()
    {
        var (client, _) = await CreateRegisteredClient();
        using (client)
        {
            var order = await client.GetOrderAsync(new Uri("https://acme.test/order/1"));
            Assert.Equal("pending", order.Status);

            var authorization = await client.GetAuthorizationAsync(new Uri("https://acme.test/authz/1"));
            Assert.Equal("pending", authorization.Status);
            Assert.Equal("example.com", authorization.Identifier!.Value);
            Assert.Single(authorization.Challenges!);
            Assert.Equal("dns-01", authorization.Challenges![0].Type);

            var challenge = await client.GetChallengeAsync(new Uri("https://acme.test/challenge/1"));
            Assert.Equal("valid", challenge.Status);
            Assert.Equal("tok_abc", challenge.Token);
        }
    }

    [Fact]
    public async Task ValidateChallengeAsync_ReturnsValidatedChallenge()
    {
        var (client, server) = await CreateRegisteredClient();
        using (client)
        {
            var challenge = await client.ValidateChallengeAsync(new Uri("https://acme.test/challenge/1"));

            Assert.Equal("valid", challenge.Status);
            Assert.NotNull(challenge.Validated);

            // RFC 8555 §7.5.1：触发验证必须 POST 空对象 {}，空 payload 会被 LE 当作 POST-as-GET（不触发验证）
            var payload = Encoding.UTF8.GetString(Base64UrlText.Decode(server.LastPayload!));
            Assert.Equal("{}", payload);
        }
    }

    [Fact]
    public async Task FinalizeAsync_SubmitsCsrDer()
    {
        var (client, server) = await CreateRegisteredClient();
        using (client)
        {
            using var certKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);
            var csr = CsrBuilder.CreateSigningRequestDer(certKey, "example.com", new[] { "example.com" });

            var order = await client.FinalizeAsync(new Uri("https://acme.test/finalize/1"), csr);

            Assert.Equal("processing", order.Status);
            Assert.Equal("https://acme.test/cert/1", order.Certificate);

            // payload 中 csr 为 base64url 编码的 DER
            var payload = Base64UrlText.Decode(server.LastPayload!);
            using var doc = JsonDocument.Parse(payload);
            var csrB64 = doc.RootElement.GetProperty("csr").GetString();
            Assert.Equal(csr, Base64UrlText.Decode(csrB64!));
        }
    }

    [Fact]
    public async Task DownloadCertificatePemAsync_ReturnsPem()
    {
        var (client, _) = await CreateRegisteredClient();
        using (client)
        {
            var pem = await client.DownloadCertificatePemAsync(new Uri("https://acme.test/cert/1"));

            Assert.Contains("BEGIN CERTIFICATE", pem);
        }
    }

    [Fact]
    public async Task DownloadCertificateAsync_ReturnsChainAndKey()
    {
        var (client, _) = await CreateRegisteredClient();
        using (client)
        {
            using var certKey = AcmeKey.Generate(AcmeKeyAlgorithm.RS256);
            using var result = await client.DownloadCertificateAsync(new Uri("https://acme.test/cert/1"), certKey);

            Assert.Contains("BEGIN CERTIFICATE", result.LeafCertificatePem);
            Assert.Contains("BEGIN CERTIFICATE", result.FullChainPem);
            Assert.Contains("PRIVATE KEY", result.PrivateKeyPem);
        }
    }

    [Fact]
    public void AcmeCertificateResult_ExportPfx_ReturnsValidPfx()
    {
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var certRequest = new CertificateRequest(new X500DistinguishedName("CN=acme.test"), ecdsa, HashAlgorithmName.SHA256);
        using var cert = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
        var chainPem = cert.ExportCertificatePem() + Environment.NewLine + cert.ExportCertificatePem();
        using var key = AcmeKey.FromPem(ecdsa.ExportPkcs8PrivateKeyPem());
        using var result = AcmeCertificateResult.FromPem(chainPem, key);

        var pfx = result.ExportPfx();
        Assert.NotEmpty(pfx);

        using var loaded = X509CertificateLoader.LoadPkcs12(pfx, null);
        Assert.True(loaded.HasPrivateKey);
    }

    [Fact]
    public async Task RevokeCertificateAsync_WithAccountKey_UsesKid()
    {
        var (client, server) = await CreateRegisteredClient();
        using (client)
        {
            var certDer = Encoding.UTF8.GetBytes("dummy-certificate-der");

            await client.RevokeCertificateAsync(certDer, AcmeRevocationReason.CessationOfOperation);

            Assert.Contains("/revoke-cert", server.PostPaths);
            Assert.Contains("\"kid\"", server.LastProtectedHeader!);
            Assert.DoesNotContain("\"jwk\"", server.LastProtectedHeader!);

            var payload = Base64UrlText.Decode(server.LastPayload!);
            using var doc = JsonDocument.Parse(payload);
            Assert.Equal(5, doc.RootElement.GetProperty("reason").GetInt32());
        }
    }

    [Fact]
    public async Task RevokeCertificateAsync_WithCertificateKey_UsesJwk()
    {
        var (client, server) = await CreateRegisteredClient();
        using (client)
        {
            var certDer = Encoding.UTF8.GetBytes("dummy-certificate-der");
            using var certKey = AcmeKey.Generate(AcmeKeyAlgorithm.ES256);

            await client.RevokeCertificateAsync(certDer, AcmeRevocationReason.KeyCompromise, certKey);

            Assert.Contains("\"jwk\"", server.LastProtectedHeader!);
        }
    }

    [Fact]
    public async Task GetAccountAsync_BeforeRegistration_Throws()
    {
        var (client, _) = CreateClient();
        using (client)
        {
            await Assert.ThrowsAsync<AcmeException>(() => client.GetAccountAsync());
        }
    }

    [Fact]
    public async Task ServerProblem_ThrowsAcmeException_WithTypeAndStatus()
    {
        var (client, server) = CreateClient();
        server.FailNextPost = true;
        using (client)
        {
            var ex = await Assert.ThrowsAsync<AcmeException>(() =>
                client.NewAccountAsync(new[] { "mailto:admin@example.com" }, true));

            Assert.Equal("urn:ietf:params:acme:error:unauthorized", ex.ErrorType);
            Assert.Equal("account not authorized", ex.Detail);
            Assert.Equal(403, ex.HttpStatus);
        }
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var (client, _) = CreateClient();
        client.Dispose();
        client.Dispose();
    }

    [Fact]
    public void FactoryMethods_ConfigureKnownEndpoints()
    {
        using var le = AcmeClient.CreateLetsEncrypt(AcmeKey.Generate(AcmeKeyAlgorithm.ES256));
        Assert.Equal(AcmeEndpoints.LetsEncrypt, le.DirectoryUrl.AbsoluteUri);

        using var staging = AcmeClient.CreateLetsEncryptStaging(AcmeKey.Generate(AcmeKeyAlgorithm.ES256));
        Assert.Equal(AcmeEndpoints.LetsEncryptStaging, staging.DirectoryUrl.AbsoluteUri);

        using var zero = AcmeClient.CreateZeroSsl(AcmeKey.Generate(AcmeKeyAlgorithm.ES256));
        Assert.Equal(AcmeEndpoints.ZeroSsl, zero.DirectoryUrl.AbsoluteUri);
    }
}
