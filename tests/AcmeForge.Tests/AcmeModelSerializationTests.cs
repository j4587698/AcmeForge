using System.Text.Json;
using AcmeForge;
using AcmeForge.Resources;

namespace AcmeForge.Tests;

public class AcmeModelSerializationTests
{
    [Fact]
    public void Deserialize_Directory_RealisticJson()
    {
        const string json = """
            {
              "newNonce": "https://acme-v02.api.letsencrypt.org/acme/new-nonce",
              "newAccount": "https://acme-v02.api.letsencrypt.org/acme/new-acct",
              "newOrder": "https://acme-v02.api.letsencrypt.org/acme/new-order",
              "revokeCert": "https://acme-v02.api.letsencrypt.org/acme/revoke-cert",
              "keyChange": "https://acme-v02.api.letsencrypt.org/acme/key-change",
              "renewalInfo": "https://acme-v02.api.letsencrypt.org/draft-ietf-acme-ari-03/renewalInfo",
              "meta": {
                "termsOfService": "https://letsencrypt.org/documents/LE-SA-v1.5-February-24-2025.pdf",
                "website": "https://letsencrypt.org",
                "caaIdentities": ["letsencrypt.org"],
                "externalAccountRequired": false
              }
            }
            """;

        var directory = JsonSerializer.Deserialize(json, AcmeJsonContext.Instance.AcmeDirectory);

        Assert.NotNull(directory);
        Assert.Equal("https://acme-v02.api.letsencrypt.org/acme/new-nonce", directory!.NewNonce);
        Assert.Equal("https://acme-v02.api.letsencrypt.org/acme/new-order", directory.NewOrder);
        Assert.Equal("https://acme-v02.api.letsencrypt.org/acme/revoke-cert", directory.RevokeCert);
        Assert.False(directory.Meta!.ExternalAccountRequired);
        Assert.Contains("letsencrypt.org", directory.Meta.CaaIdentities!);
    }

    [Fact]
    public void Deserialize_Account()
    {
        const string json = """
            {"status":"valid","contact":["mailto:cert-admin@example.com","mailto:admin@example.com"],"orders":"https://acme.test/orders","termsOfServiceAgreed":true}
            """;

        var account = JsonSerializer.Deserialize(json, AcmeJsonContext.Instance.AcmeAccount);

        Assert.Equal("valid", account!.Status);
        Assert.Equal(2, account.Contact!.Length);
        Assert.Equal("mailto:cert-admin@example.com", account.Contact[0]);
        Assert.True(account.TermsOfServiceAgreed);
        Assert.Equal("https://acme.test/orders", account.Orders);
    }

    [Fact]
    public void Deserialize_Order()
    {
        const string json = """
            {
              "status": "pending",
              "expires": "2026-03-01T00:00:00Z",
              "identifiers": [{"type":"dns","value":"example.com"},{"type":"dns","value":"*.example.com"}],
              "authorizations": ["https://acme.test/authz/1","https://acme.test/authz/2"],
              "finalize": "https://acme.test/finalize/1"
            }
            """;

        var order = JsonSerializer.Deserialize(json, AcmeJsonContext.Instance.AcmeOrder);

        Assert.Equal("pending", order!.Status);
        Assert.Equal(2, order.Identifiers!.Length);
        Assert.Equal("*.example.com", order.Identifiers[1].Value);
        Assert.Equal(2, order.Authorizations!.Length);
        Assert.Equal("https://acme.test/finalize/1", order.Finalize);
        Assert.Null(order.Certificate);
    }

    [Fact]
    public void Deserialize_Authorization_WithWildcard()
    {
        const string json = """
            {
              "identifier": {"type":"dns","value":"example.com"},
              "status": "valid",
              "expires": "2026-03-01T00:00:00Z",
              "wildcard": true,
              "challenges": [
                {"type":"dns-01","url":"https://acme.test/challenge/1","status":"pending","token":"DGyRejmCefe7v4NfDGDKfA"},
                {"type":"http-01","url":"https://acme.test/challenge/2","status":"valid","token":"abc123","validated":"2026-01-01T00:00:00Z"}
              ]
            }
            """;

        var authorization = JsonSerializer.Deserialize(json, AcmeJsonContext.Instance.AcmeAuthorization);

        Assert.Equal("example.com", authorization!.Identifier!.Value);
        Assert.True(authorization.Wildcard);
        Assert.Equal(2, authorization.Challenges!.Length);
        Assert.Equal("dns-01", authorization.Challenges[0].Type);
        Assert.Equal("DGyRejmCefe7v4NfDGDKfA", authorization.Challenges[0].Token);
        Assert.Equal("valid", authorization.Challenges[1].Status);
    }

    [Fact]
    public void Deserialize_Problem_Rfc7807()
    {
        const string json = """
            {
              "type": "urn:ietf:params:acme:error:rateLimited",
              "detail": "Error creating new order :: too many certificates (5) already issued for this exact set of domains",
              "status": 429,
              "identifier": {"type":"dns","value":"example.com"},
              "subproblems": [
                {"type":"urn:ietf:params:acme:error:rateLimited","detail":"subproblem detail","status":429}
              ]
            }
            """;

        var problem = JsonSerializer.Deserialize(json, AcmeJsonContext.Instance.AcmeProblem);

        Assert.Equal("urn:ietf:params:acme:error:rateLimited", problem!.Type);
        Assert.Contains("too many certificates", problem.Detail);
        Assert.Equal(429, problem.Status);
        Assert.Equal("example.com", problem.Identifier!.Value);
        Assert.Single(problem.Subproblems!);
        Assert.Equal("subproblem detail", problem.Subproblems![0].Detail);
    }

    [Fact]
    public void RoundTrip_Directory_SerializesAndDeserializes()
    {
        var directory = new AcmeDirectory
        {
            NewNonce = "https://acme.test/new-nonce",
            NewAccount = "https://acme.test/new-account",
            NewOrder = "https://acme.test/new-order",
            RevokeCert = "https://acme.test/revoke-cert",
            Meta = new AcmeDirectoryMeta
            {
                TermsOfService = "https://acme.test/terms",
                ExternalAccountRequired = true,
                CaaIdentities = new[] { "acme.test" },
            },
        };

        var json = JsonSerializer.Serialize(directory, AcmeJsonContext.Instance.AcmeDirectory);
        var roundTrip = JsonSerializer.Deserialize(json, AcmeJsonContext.Instance.AcmeDirectory);

        Assert.Equal(directory.NewNonce, roundTrip!.NewNonce);
        Assert.Equal(directory.Meta.TermsOfService, roundTrip.Meta!.TermsOfService);
        Assert.True(roundTrip.Meta.ExternalAccountRequired);
    }

    [Fact]
    public void Serialize_Directory_ProducesCamelCaseJson()
    {
        var directory = new AcmeDirectory { NewNonce = "n", NewAccount = "a" };
        var json = JsonSerializer.Serialize(directory, AcmeJsonContext.Instance.AcmeDirectory);

        Assert.Contains("\"newNonce\":", json);
        Assert.Contains("\"newAccount\":", json);
    }
}
