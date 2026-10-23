using System.Net;

namespace NetScope.Core;

/// <summary>
/// Fictional hosts for screenshots. Loaded only when the process is started with <see cref="Flag"/>.
/// </summary>
public static class DemoCatalog
{
    public const string Flag = "--demo";

    public sealed record Sample(IReadOnlyList<HostResult> Hosts, IReadOnlyDictionary<string, SmbEnumerationResult> Shares);

    public static Sample Create()
    {
        var desktop = Host("192.168.1.10", "DESKTOP-DEMO01", "18:66:DA:10:00:01", "Dell Inc.", 4,
            Port(22, "SSH-2.0-OpenSSH_9.6"),
            Port(80, "HTTP/1.1 200 OK"),
            Port(443),
            Port(445),
            Port(3389));
        var nas = Host("192.168.1.15", "nas-demo", "00:11:32:15:00:02", "Synology Incorporated", 6,
            Port(22, "SSH-2.0-OpenSSH_8.2"),
            Port(80),
            Port(443),
            Port(445),
            Port(5001));
        var printer = Host("192.168.1.20", "printer-demo", "00:00:48:20:00:03", "Seiko Epson Corporation", 11,
            Port(80),
            Port(443),
            Port(515),
            Port(9100));
        var files = Host("192.168.1.25", "files-demo", "00:0C:29:25:00:04", "VMware, Inc.", 5,
            Port(139),
            Port(445));
        var camera = Host("192.168.1.30", "camera-demo", "B8:27:EB:30:00:05", "Raspberry Pi Foundation", 18,
            Port(80),
            Port(443),
            Port(554));
        var laptop = Host("192.168.1.40", "laptop-demo", "3C:22:FB:40:00:06", "Apple, Inc.", 2,
            Port(22, "SSH-2.0-OpenSSH_9.7"),
            Port(3389));
        var gateway = Host("192.168.1.50", "gateway-demo", "00:00:0C:50:00:07", "Cisco Systems, Inc", 1,
            Port(22),
            Port(53),
            Port(80),
            Port(443));
        var phone = Host("192.168.1.60", "phone-demo", "B4:F1:DA:60:00:08", "Google, Inc.", 21,
            Port(5060),
            Port(8080));

        var shares = new Dictionary<string, SmbEnumerationResult>(StringComparer.Ordinal)
        {
            [desktop.Address.ToString()] = SmbEnumerationResult.Ok(new[]
            {
                SmbShareClassifier.Create("Public", 0, "Demo documents"),
                SmbShareClassifier.Create("Users", 0, "Demo user profiles"),
                SmbShareClassifier.Create("C$", 0x80000000, "Default share"),
                SmbShareClassifier.Create("IPC$", 0x80000003, "Remote IPC")
            }),
            [nas.Address.ToString()] = SmbEnumerationResult.Ok(new[]
            {
                SmbShareClassifier.Create("media", 0, "Demo media library"),
                SmbShareClassifier.Create("backups", 0, "Demo backups")
            }),
            [files.Address.ToString()] = SmbEnumerationResult.Ok(new[]
            {
                SmbShareClassifier.Create("Projects", 0, "Demo project files")
            })
        };

        return new Sample(
            new[] { desktop, nas, printer, files, camera, laptop, gateway, phone },
            shares);
    }

    private static HostResult Host(string ip, string name, string mac, string vendor, long latency, params OpenPort[] ports)
    {
        var host = new HostResult
        {
            Address = IPAddress.Parse(ip),
            DnsName = name,
            MacAddress = mac,
            Vendor = vendor,
            LatencyMs = latency
        };
        host.Ports.AddRange(ports);
        return host;
    }

    private static OpenPort Port(int number, string? banner = null)
        => new(number, ServiceNames.Resolve(number, banner), banner, BannerClassifier.IsSsh(banner));
}
