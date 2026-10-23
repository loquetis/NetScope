using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetScope.Core;

public static class ResultExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static string ToCsv(IEnumerable<HostResult> hosts)
    {
        var builder = new StringBuilder();
        builder.AppendLine(ResultColumns.CsvHeaderLine);
        foreach (var host in hosts)
        {
            var ports = host.CopyPorts();
            builder.Append(Csv(host.Address.ToString())).Append(',')
                .Append(Csv(host.Hostname)).Append(',')
                .Append(Csv(host.DnsName)).Append(',')
                .Append(Csv(host.NetBiosName)).Append(',')
                .Append(Csv(host.MdnsName)).Append(',')
                .Append(Csv(host.MacAddress)).Append(',')
                .Append(Csv(host.Vendor)).Append(',')
                .Append(host.LatencyMs?.ToString(CultureInfo.InvariantCulture) ?? "").Append(',')
                .Append(Csv(FormatPorts(ports))).Append(',')
                .Append(Csv(FormatBanners(ports)))
                .AppendLine();
        }

        return builder.ToString();
    }

    public static string ToJson(IEnumerable<HostResult> hosts)
    {
        var rows = hosts.Select(host =>
        {
            var ports = host.CopyPorts();
            return new ExportRow(
                host.Address.ToString(),
                host.Hostname,
                host.DnsName,
                host.NetBiosName,
                host.MdnsName,
                host.MacAddress,
                host.Vendor,
                host.LatencyMs,
                ports.OrderBy(port => port.Number).Select(port => new ExportPort(
                    port.Number,
                    port.Service,
                    port.Banner,
                    port.IsSsh,
                    port.IsRdp,
                    port.IsSmb)).ToArray());
        });
        return JsonSerializer.Serialize(rows, JsonOptions);
    }

    private sealed record ExportRow(
        [property: JsonPropertyName(ResultColumns.IpAddress)] string IpAddress,
        [property: JsonPropertyName(ResultColumns.Hostname)] string Hostname,
        [property: JsonPropertyName(ResultColumns.DnsName)] string? DnsName,
        [property: JsonPropertyName(ResultColumns.NetBiosName)] string? NetBiosName,
        [property: JsonPropertyName(ResultColumns.MdnsName)] string? MdnsName,
        [property: JsonPropertyName(ResultColumns.MacAddress)] string? MacAddress,
        [property: JsonPropertyName(ResultColumns.Vendor)] string? Vendor,
        [property: JsonPropertyName(ResultColumns.Latency)] long? LatencyMs,
        [property: JsonPropertyName(ResultColumns.OpenPorts)] ExportPort[] OpenPorts);

    private sealed record ExportPort(
        int Port,
        string Service,
        string? Banner,
        bool Ssh,
        bool Rdp,
        bool Smb);

    public static string Csv(string? value)
    {
        value ??= "";
        if (value.Contains('"') || value.Contains(',') || value.Contains('\n') || value.Contains('\r'))
            return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        return value;
    }

    private static string FormatPorts(IReadOnlyList<OpenPort> ports)
        => ports.Count == 0 ? "" : string.Join(", ", ports.OrderBy(port => port.Number).Select(port => $"{port.Number}/{port.Service}"));

    private static string FormatBanners(IReadOnlyList<OpenPort> ports)
        => string.Join(" | ", ports.Where(port => !string.IsNullOrWhiteSpace(port.Banner)).OrderBy(port => port.Number).Select(port => $"{port.Number} {port.Banner}"));
}
