using System;

namespace AcmeForge.Dns;

/// <summary>
/// 域名解析辅助方法：提取注册域(zone) 与 相对子域(host)。
/// 内置小型公共后缀集合以识别多标签公共后缀（co.uk / com.cn 等），
/// 避免对多标签后缀域名取错 zone。AOT 安全，无反射。
/// </summary>
internal static class DnsDomainHelper
{
    // 常见多标签公共后缀（PSL 子集）。不在此集合中的域名按"末两段为根域"处理。
    private static readonly System.Collections.Generic.HashSet<string> MultiLabelPublicSuffixes =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // UK
            "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "ac.uk", "gov.uk", "sch.uk",
            // CN
            "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
            // JP
            "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
            // AU
            "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
            // NZ
            "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "gen.nz", "geek.nz", "school.nz",
            // HK
            "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk", "idv.hk",
            // TW
            "com.tw", "org.tw", "net.tw", "edu.tw", "gov.tw", "idv.tw",
            // IN
            "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in", "edu.in", "gov.in", "res.in",
            // BR
            "com.br", "net.br", "org.br", "gov.br", "edu.br",
            // RU
            "com.ru", "net.ru", "org.ru", "pp.ru",
            // SG
            "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
            // MY
            "com.my", "net.my", "org.my", "edu.my", "gov.my",
            // ID
            "co.id", "or.id", "web.id", "sch.id", "ac.id", "go.id", "mil.id", "net.id",
            // KR
            "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr", "re.kr", "pe.kr",
            // Other
            "co.za", "com.mx", "com.ar", "co.th", "com.ph", "com.vn", "com.tr", "com.co",
        };

    /// <summary>
    /// 提取注册域（zone）。自动去掉 *. 通配符前缀，并对多标签公共后缀（co.uk 等）正确处理。
    /// 例如：example.com → example.com；sub.example.com → example.com；
    /// example.co.uk → example.co.uk；*.example.com → example.com。
    /// </summary>
    public static string ExtractRootDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return domain ?? string.Empty;
        }

        if (domain.StartsWith("*.", StringComparison.Ordinal))
        {
            domain = domain[2..];
        }

        domain = domain.TrimEnd('.');

        var parts = domain.Split('.');
        if (parts.Length < 2)
        {
            return domain;
        }

        var lastTwo = string.Join(".", parts[^2], parts[^1]);
        if (MultiLabelPublicSuffixes.Contains(lastTwo))
        {
            // 多标签公共后缀：注册域 = 后缀前的一段 + 后缀
            return parts.Length >= 3
                ? string.Join(".", parts[^3], lastTwo)
                : lastTwo;
        }

        return lastTwo;
    }

    /// <summary>
    /// 从完整记录名提取相对子域（host）。rootDomain 为注册域/zone。
    /// recordName == rootDomain 时返回 "@"。
    /// 无法匹配 rootDomain 时回退为移除末两段（旧逻辑）。
    /// </summary>
    public static string ExtractSubDomain(string recordName, string rootDomain)
    {
        if (string.IsNullOrEmpty(recordName))
        {
            return recordName ?? string.Empty;
        }

        if (!string.IsNullOrEmpty(rootDomain))
        {
            if (recordName.Equals(rootDomain, StringComparison.OrdinalIgnoreCase))
            {
                return "@";
            }

            var suffix = "." + rootDomain;
            if (recordName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return recordName[..^suffix.Length];
            }
        }

        var parts = recordName.Split('.');
        if (parts.Length > 2)
        {
            return string.Join(".", parts[..^2]);
        }

        return recordName;
    }
}
