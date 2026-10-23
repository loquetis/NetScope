namespace NetScope.Core;

/// <summary>
/// Display names for the results grid and for CSV/JSON export.
/// Grid columns use the first six. Export adds the name sources and banners.
/// </summary>
public static class ResultColumns
{
    public const string IpAddress = "IP Address";
    public const string Hostname = "Hostname";
    public const string MacAddress = "MAC Address";
    public const string Vendor = "Vendor";
    public const string Latency = "Latency (ms)";
    public const string OpenPorts = "Open Ports";
    public const string DnsName = "DNS Name";
    public const string NetBiosName = "NetBIOS Name";
    public const string MdnsName = "mDNS Name";
    public const string Banners = "Banners";

    public static readonly string[] Grid =
    [
        IpAddress,
        Hostname,
        MacAddress,
        Vendor,
        Latency,
        OpenPorts
    ];

    public static readonly string[] Csv =
    [
        IpAddress,
        Hostname,
        DnsName,
        NetBiosName,
        MdnsName,
        MacAddress,
        Vendor,
        Latency,
        OpenPorts,
        Banners
    ];

    public static string CsvHeaderLine => string.Join(',', Csv);
}
