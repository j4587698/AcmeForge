using System.Text.Json;
using AcmeForge.Dns;

namespace AcmeForge.Tests;

public class DnsDtoSerializationTests
{
    [Fact]
    public void Cloudflare_RecordRequest_SerializesWithExpectedFields()
    {
        var request = new CloudflareDnsRecordRequest
        {
            Name = "_acme-challenge.example.com",
            Content = "txt-value-abc",
            Ttl = 120,
        };

        var json = JsonSerializer.Serialize(request, DnsJsonContext.Instance.CloudflareDnsRecordRequest);

        Assert.Contains("\"type\":\"TXT\"", json);
        Assert.Contains("\"name\":\"_acme-challenge.example.com\"", json);
        Assert.Contains("\"content\":\"txt-value-abc\"", json);
        Assert.Contains("\"ttl\":120", json);
    }

    [Fact]
    public void Cloudflare_DnsRecordsResponse_Deserializes()
    {
        const string json = """
            {"success":true,"result":[{"id":"r1","type":"TXT","name":"_acme-challenge.example.com","content":"v1","ttl":120,"proxied":false,"created_on":"2026-01-01T00:00:00Z","modified_on":"2026-01-01T00:00:00Z"}],"errors":[],"messages":[]}
            """;

        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.CloudflareDnsRecordsResponse);

        Assert.True(response!.Success);
        var record = Assert.Single(response.Result!);
        Assert.Equal("TXT", record.Type);
        Assert.Equal("v1", record.Content);
    }

    [Fact]
    public void GoDaddy_DnsRecords_SerializeList()
    {
        var records = new List<GoDaddyDnsRecord>
        {
            new() { Name = "_acme-challenge.example.com", Type = "TXT", Data = "v1", Ttl = 120 },
            new() { Name = "_acme-challenge.example.com", Type = "TXT", Data = "v2", Ttl = 120 },
        };

        var json = JsonSerializer.Serialize(records, DnsJsonContext.Instance.ListGoDaddyDnsRecord);

        Assert.Contains("\"name\":\"_acme-challenge.example.com\"", json);
        Assert.Contains("\"type\":\"TXT\"", json);
        Assert.Contains("\"data\":\"v1\"", json);
        Assert.Contains("\"ttl\":120", json);
    }

    [Fact]
    public void GoDaddy_ListRoundTrips()
    {
        var records = new List<GoDaddyDnsRecord> { new() { Name = "n", Type = "TXT", Data = "d", Ttl = 300 } };
        var json = JsonSerializer.Serialize(records, DnsJsonContext.Instance.ListGoDaddyDnsRecord);
        var roundTrip = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.ListGoDaddyDnsRecord);

        var record = Assert.Single(roundTrip!);
        Assert.Equal("n", record.Name);
        Assert.Equal("d", record.Data);
        Assert.Equal(300, record.Ttl);
    }

    [Fact]
    public void Tencent_CreateRecordRequest_KeepsExactPascalCaseFieldNames()
    {
        var request = new TencentCreateRecordRequest
        {
            DomainId = "domain-1",
            SubDomain = "_acme-challenge",
            RecordType = "TXT",
            RecordValue = "v1",
            TTL = 120,
        };

        var json = JsonSerializer.Serialize(request, DnsJsonContext.Instance.TencentCreateRecordRequest);

        // Tencent TC3 API 需要与签名一致的精确字段名（PascalCase）
        Assert.Contains("\"DomainId\":\"domain-1\"", json);
        Assert.Contains("\"SubDomain\":\"_acme-challenge\"", json);
        Assert.Contains("\"RecordType\":\"TXT\"", json);
        Assert.Contains("\"RecordValue\":\"v1\"", json);
        Assert.Contains("\"TTL\":120", json);
    }

    [Fact]
    public void Tencent_ModifyAndDelete_PreserveFieldNames()
    {
        var modify = new TencentModifyRecordRequest { DomainId = "d", RecordId = "r", TTL = 120 };
        var delete = new TencentDeleteRecordRequest { DomainId = "d", RecordId = "r" };
        var describe = new TencentDescribeRecordListRequest { DomainId = "d", Subdomain = "_acme-challenge", RecordType = "TXT" };

        var modifyJson = JsonSerializer.Serialize(modify, DnsJsonContext.Instance.TencentModifyRecordRequest);
        var deleteJson = JsonSerializer.Serialize(delete, DnsJsonContext.Instance.TencentDeleteRecordRequest);
        var describeJson = JsonSerializer.Serialize(describe, DnsJsonContext.Instance.TencentDescribeRecordListRequest);

        Assert.Contains("\"RecordId\":\"r\"", modifyJson);
        Assert.Contains("\"TTL\":120", modifyJson);
        Assert.Contains("\"RecordId\":\"r\"", deleteJson);
        Assert.Contains("\"Subdomain\":\"_acme-challenge\"", describeJson);
    }

    [Fact]
    public void Tencent_RecordsResponse_Deserializes()
    {
        const string json = """
            {"Response":{"RequestId":"req-1","TotalCount":1,"RecordList":[{"RecordId":"rec-1","Name":"_acme-challenge","Type":"TXT","Value":"v1","TTL":120,"Status":"enable"}],"Error":null}}
            """;

        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.TencentRecordsResponse);

        Assert.Equal(1, response!.Response!.TotalCount);
        var record = Assert.Single(response.Response.RecordList!);
        Assert.Equal("rec-1", record.RecordId);
        Assert.Equal("_acme-challenge", record.SubDomain);
        Assert.Equal("TXT", record.RecordType);
        Assert.Equal("v1", record.RecordValue);
    }

    [Fact]
    public void Tencent_ErrorResponse_Deserializes()
    {
        const string json = """
            {"Response":{"RequestId":"req-1","Error":{"Code":"AuthFailure.SecretIdNotFound","Message":"secret id not found"}}}
            """;

        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.TencentDnsResponse);

        Assert.Equal("AuthFailure.SecretIdNotFound", response!.Response!.Error!.Code);
        Assert.Equal("secret id not found", response.Response.Error.Message);
    }

    [Fact]
    public void Azure_RecordSetRequest_SerializesNestedStructure()
    {
        var request = new AzureDnsRecordSetRequest
        {
            Properties = new AzureDnsRecordSetProperties
            {
                TTL = 120,
                TXTRecords = new List<AzureTxtRecordValue> { new() { Value = new List<string> { "v1" } } },
            },
        };

        var json = JsonSerializer.Serialize(request, DnsJsonContext.Instance.AzureDnsRecordSetRequest);

        Assert.Contains("\"TTL\":120", json);
        Assert.Contains("\"TXTRecords\"", json);
        Assert.Contains("\"value\":[\"v1\"]", json);
    }

    [Fact]
    public void Azure_TokenResponse_Deserializes()
    {
        const string json = """{"access_token":"abc","expires_in":3599,"token_type":"Bearer"}""";
        var token = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.AzureTokenResponse);

        Assert.Equal("abc", token!.AccessToken);
        Assert.Equal(3599, token.ExpiresIn);
        Assert.Equal("Bearer", token.TokenType);
    }

    [Fact]
    public void Aliyun_DomainsResponse_Deserializes()
    {
        // 阿里云 DescribeDomains 的数组包装在 Domains.Domain 下。
        const string json = """
            {"RequestId":"req","Success":true,"Domains":{"Domain":[{"DomainId":"d1","DomainName":"example.com","DnsServers":["ns1","ns2"],"DomainAuditStatus":"SUCCESS"}]},"TotalCount":1}
            """;

        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.AliyunDomainsResponse);

        var domain = Assert.Single(response!.Domains!.Domain!);
        Assert.Equal("example.com", domain.DomainName);
    }

    [Fact]
    public void Aliyun_DomainRecords_DeserializesRealShape()
    {
        // DescribeDomainRecords 返回 DomainRecords.Record，记录 Status 为字符串。
        const string json = """
            {"RequestId":"req","Success":true,"TotalCount":1,"DomainRecords":{"Record":[{"RecordId":"r1","RR":"_acme-challenge","Type":"TXT","Value":"v1","Status":"ENABLE"}]}}
            """;

        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.AliyunRecordsResponse);

        var record = Assert.Single(response!.DomainRecords!.Record!);
        Assert.Equal("TXT", record.Type);
        Assert.Equal("ENABLE", record.Status);
    }

    [Fact]
    public void DnsPodTraditional_Deserializes()
    {
        const string listJson = """{"status":{"code":"1","message":"Action completed successful"},"domains":[{"id":"d1","name":"example.com"}]}""";
        var list = JsonSerializer.Deserialize(listJson, DnsJsonContext.Instance.DnsPodTraditionalListDomainsResponse);

        Assert.Equal("1", list!.Status!.Code);
        Assert.Equal("example.com", Assert.Single(list.Domains!).Name);

        const string recordJson = """{"status":{"code":"1"},"records":[{"id":"r1","value":"v1"}]}""";
        var records = JsonSerializer.Deserialize(recordJson, DnsJsonContext.Instance.DnsPodTraditionalListRecordsResponse);
        Assert.Equal("v1", Assert.Single(records!.Records!).Value);
    }

    [Fact]
    public void DnsPod_Deserializes()
    {
        const string json = """{"status":{"code":"1"},"domains":[{"id":"d1","name":"example.com"}]}""";
        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.DnsPodApiResponse);

        Assert.Equal("1", response!.Status.GetProperty("code").GetString());
        Assert.Equal("example.com", Assert.Single(response.Domains!).Name);
    }

    [Fact]
    public void DnsPod_NumericDomainId_DeserializesToString()
    {
        const string json = """{"status":{"code":"1"},"domains":[{"id":12345,"name":"example.com"}]}""";
        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.DnsPodApiResponse);

        Assert.Equal("12345", response!.Domains![0].Id);
    }

    [Fact]
    public void DnsPod_NumericRecordId_DeserializesToString()
    {
        const string json = """{"status":{"code":"1"},"records":[{"id":67890,"value":"v1"}]}""";
        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.DnsPodApiResponse);

        Assert.Equal("67890", response!.Records![0].Id);
    }

    [Fact]
    public void DnsPodTraditional_NumericDomainId_DeserializesToString()
    {
        const string json = """{"status":{"code":"1"},"domains":[{"id":12345,"name":"example.com"}]}""";
        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.DnsPodTraditionalListDomainsResponse);

        Assert.Equal("12345", response!.Domains![0].Id);
    }

    [Fact]
    public void Tencent_DomainsResponse_RealShape_Deserializes()
    {
        // 腾讯云 DescribeDomainList 的真实响应形状：DomainId 为数字、Name 而非 DomainName、IsVip 为字符串、计数在 DomainCountInfo.AllTotal。
        const string json = """
            {"Response":{"RequestId":"req","DomainCountInfo":{"AllTotal":1,"MineTotal":1},"DomainList":[{"DomainId":1234567,"Name":"example.com","Grade":"DP_Free","IsVip":"no","Status":"enable","RecordCount":2}],"Error":null}}
            """;

        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.TencentDomainsResponse);

        Assert.Equal(1, response!.Response!.DomainCountInfo!.AllTotal);
        var domain = Assert.Single(response.Response.DomainList!);
        Assert.Equal("1234567", domain.DomainId);
        Assert.Equal("example.com", domain.DomainName);
        Assert.Equal("no", domain.IsVip);
    }

    [Fact]
    public void Tencent_RecordsResponse_RealShape_Deserializes()
    {
        // 腾讯云 DescribeRecordList 的记录：RecordId 数字、字段为 Name/Type/Value、MX 为数字。
        const string json = """
            {"Response":{"RequestId":"req","TotalCount":1,"RecordList":[{"RecordId":162,"Name":"_acme-challenge","Type":"TXT","Value":"v1","Status":"enable","TTL":120,"MX":0}],"Error":null}}
            """;

        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.TencentRecordsResponse);

        var record = Assert.Single(response!.Response!.RecordList!);
        Assert.Equal("162", record.RecordId);
        Assert.Equal("_acme-challenge", record.SubDomain);
        Assert.Equal("TXT", record.RecordType);
        Assert.Equal("v1", record.RecordValue);
        Assert.Equal(0, record.Mx);
    }

    [Fact]
    public void Tencent_CreateRecordRequest_SerializesNumericDomainIdAndRecordLine()
    {
        var request = new TencentCreateRecordRequest
        {
            DomainId = "1234567",
            SubDomain = "_acme-challenge",
            RecordType = "TXT",
            RecordLine = "默认",
            RecordValue = "v1",
            TTL = 600,
        };

        var json = JsonSerializer.Serialize(request, DnsJsonContext.Instance.TencentCreateRecordRequest);

        // DomainId 按 API 文档为 Integer，应序列化为数字；RecordLine 为必填参数。
        Assert.Contains("\"DomainId\":1234567", json);
        Assert.Contains("\"RecordLine\":\"", json);
        Assert.Contains("\"TTL\":600", json);
    }

    [Fact]
    public void JsonStringAsNumberConverter_RoundTrips()
    {
        var request = new TencentModifyRecordRequest { DomainId = "62", RecordId = "162", TTL = 120 };
        var json = JsonSerializer.Serialize(request, DnsJsonContext.Instance.TencentModifyRecordRequest);

        Assert.Contains("\"DomainId\":62", json);
        Assert.Contains("\"RecordId\":162", json);

        var deserialized = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.TencentModifyRecordRequest);
        Assert.Equal("62", deserialized!.DomainId);
        Assert.Equal("162", deserialized.RecordId);
    }

    [Fact]
    public void DnsDomainHelper_ExtractsRootDomain()
    {
        Assert.Equal("example.com", DnsDomainHelper.ExtractRootDomain("example.com"));
        Assert.Equal("example.com", DnsDomainHelper.ExtractRootDomain("sub.example.com"));
        Assert.Equal("example.com", DnsDomainHelper.ExtractRootDomain("*.example.com"));
        Assert.Equal("example.co.uk", DnsDomainHelper.ExtractRootDomain("_acme-challenge.example.co.uk"));
        Assert.Equal("example.com.cn", DnsDomainHelper.ExtractRootDomain("www.example.com.cn"));
        Assert.Equal("example.co.jp", DnsDomainHelper.ExtractRootDomain("api.example.co.jp"));
    }

    [Fact]
    public void DnsDomainHelper_ExtractsSubDomain()
    {
        Assert.Equal("_acme-challenge", DnsDomainHelper.ExtractSubDomain("_acme-challenge.example.com", "example.com"));
        Assert.Equal("@", DnsDomainHelper.ExtractSubDomain("example.com", "example.com"));
        Assert.Equal("_acme-challenge", DnsDomainHelper.ExtractSubDomain("_acme-challenge.example.co.uk", "example.co.uk"));
        Assert.Equal("_acme-challenge.api", DnsDomainHelper.ExtractSubDomain("_acme-challenge.api.example.com", "example.com"));
    }

    [Fact]
    public void DnsPod_ChineseSuccessStatus_IsDetectedAsSuccess()
    {
        // DNSPod 中文响应 message="操作已经成功完成"，无英文字符串 "success"，code=="1" 才是成功信号。
        const string json = """{"status":{"code":"1","message":"操作已经成功完成"},"domains":[]}""";
        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.DnsPodApiResponse);

        var isSuccess = response!.Status.ValueKind == JsonValueKind.Object
            && response.Status.TryGetProperty("code", out var code)
            && code.GetRawText().Trim('"') == "1";

        Assert.True(isSuccess);
        Assert.DoesNotContain("success", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DnsPod_ErrorStatus_IsNotSuccess()
    {
        const string json = """{"status":{"code":"10","message":"记录已存在"},"domains":[]}""";
        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.DnsPodApiResponse);

        var isSuccess = response!.Status.ValueKind == JsonValueKind.Object
            && response.Status.TryGetProperty("code", out var code)
            && code.GetRawText().Trim('"') == "1";

        Assert.False(isSuccess);
    }

    [Fact]
    public void Aliyun_AddDomainRecord_SuccessResponse_HasNoSuccessField()
    {
        // 阿里云 RPC 成功响应不含 Success 字段，只有 RequestId/RecordId；失败才走非 2xx。
        const string json = """{"RequestId":"A1B2C3","RecordId":"9999985"}""";

        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.AliyunDnsResponse);

        Assert.NotNull(response);
        Assert.Equal("9999985", response!.RecordId);
        // 不存在 Success 字段时默认 false，不能用来判定成功。
        Assert.False(response.Success);
    }

    [Fact]
    public void Aliyun_DescribeDomains_SuccessResponse_HasNoSuccessField()
    {
        // 阿里云 DescribeDomains 真实响应：数组在 Domains.Domain 下，且成功响应不含 Success 字段。
        const string json = """{"RequestId":"A1B2C3","Domains":{"Domain":[{"DomainId":"d1","DomainName":"example.com"}]}}""";

        var response = JsonSerializer.Deserialize(json, DnsJsonContext.Instance.AliyunDomainsResponse);

        Assert.NotNull(response);
        Assert.False(response!.Success);
    }
}