using System.Net;

namespace NetScope.Core;

public sealed class HostResult
{
    public required IPAddress Address { get; init; }
    public string? DnsName { get; set; }
    public string? NetBiosName { get; set; }
    public string? MdnsName { get; set; }
    public string? MacAddress { get; set; }
    public string? Vendor { get; set; }
    public long? LatencyMs { get; set; }
    public List<OpenPort> Ports { get; } = new();

    public string Hostname
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(DnsName)) return DnsName!;
            if (!string.IsNullOrWhiteSpace(NetBiosName)) return NetBiosName!;
            if (!string.IsNullOrWhiteSpace(MdnsName)) return MdnsName!;
            return "";
        }
    }

    public IReadOnlyList<OpenPort> CopyPorts()
    {
        lock (Ports)
            return Ports.ToArray();
    }

    public string PortsSummary
    {
        get
        {
            var ports = CopyPorts();
            if (ports.Count == 0) return "";
            return string.Join(", ", ports.OrderBy(p => p.Number).Select(p => $"{p.Number}/{p.Service}"));
        }
    }
}

public sealed record OpenPort(int Number, string Service, string? Banner, bool SshDetected)
{
    public bool IsRdp => Number == 3389;
    public bool IsSsh => SshDetected || Number == 22;
    public bool IsSmb => Number is 445 or 139;
}

public enum PortSelectionMode
{
    Common,
    All,
    Custom
}

public sealed record ScanOptions(int Concurrency, int TimeoutMs, bool GrabBanners);

public sealed record ScanProgress(string Phase, int Completed, int Total);

public static class ScanLimits
{
    public const int MaxHosts = 65536;
    public const int MinConcurrency = 1;
    public const int MaxConcurrency = 512;
    public const int DefaultConcurrency = 128;
    public const int MinTimeoutMs = 50;
    public const int MaxTimeoutMs = 10_000;
    public const int DefaultTimeoutMs = 400;
    public const int PingTimeoutMs = 700;
    public const int BannerTimeoutMs = 250;
    public const int NameTimeoutMs = 450;
    public const long LargeScanThreshold = 250_000;

    public static void ValidateConcurrency(int value)
    {
        if (value < MinConcurrency || value > MaxConcurrency)
            throw new ArgumentOutOfRangeException(nameof(value), $"Concurrency must be between {MinConcurrency} and {MaxConcurrency}.");
    }

    public static void ValidateTimeout(int value)
    {
        if (value < MinTimeoutMs || value > MaxTimeoutMs)
            throw new ArgumentOutOfRangeException(nameof(value), $"Timeout must be between {MinTimeoutMs} and {MaxTimeoutMs} ms.");
    }
}
