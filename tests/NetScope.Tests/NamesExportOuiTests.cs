using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using NetScope.Core;

namespace NetScope.Tests;

public class NamePacketTests
{
    [Fact]
    public void Netbios_query_uses_the_wildcard_and_nbstat_type()
    {
        var packet = NetBiosNames.BuildNodeStatusQuery(0x1234);
        Assert.Equal(50, packet.Length);
        Assert.Equal(0x12, packet[0]);
        Assert.Equal(0x34, packet[1]);
        Assert.Equal(1, packet[5]);
        Assert.Equal(32, packet[12]);
        Assert.StartsWith("CK", Encoding.ASCII.GetString(packet, 13, 32));
        Assert.Equal(0x00, packet[46]);
        Assert.Equal(0x21, packet[47]);
        Assert.Equal(0x01, packet[49]);
    }

    [Fact]
    public void Parses_the_unique_workstation_name_and_skips_group_names()
    {
        var packet = NodeStatus(("TESTPC", 0x00, false), ("DOMAIN", 0x00, true));
        Assert.Equal("TESTPC", NetBiosNames.ParseNodeStatusResponse(packet));

        var groupOnly = NodeStatus(("WORKGROUP", 0x00, true));
        Assert.Null(NetBiosNames.ParseNodeStatusResponse(groupOnly));
    }

    [Fact]
    public void Mdns_ptr_response_yields_the_hostname()
    {
        var question = DnsPackets.EncodeName("10.1.168.192.in-addr.arpa");
        var answer = DnsPackets.EncodeName("livingroom.local");
        var packet = new byte[12 + question.Length + 4 + 12 + answer.Length];
        packet[0] = 0x12;
        packet[1] = 0x34;
        packet[2] = 0x84;
        packet[5] = 1;
        packet[7] = 1;
        question.CopyTo(packet, 12);
        var offset = 12 + question.Length;
        packet[offset + 1] = 12;
        packet[offset + 3] = 1;
        offset += 4;
        packet[offset++] = 0xC0;
        packet[offset++] = 12;
        packet[offset++] = 0;
        packet[offset++] = 12;
        packet[offset++] = 0;
        packet[offset++] = 1;
        offset += 4;
        packet[offset++] = 0;
        packet[offset++] = (byte)answer.Length;
        answer.CopyTo(packet, offset);

        var names = DnsPackets.ReadPtrAnswers(packet);
        Assert.Equal("livingroom", DnsPackets.ChooseHostname(names));
        Assert.Equal("10.1.168.192.in-addr.arpa", DnsPackets.ReverseArpa(IPAddress.Parse("192.168.1.10")));
        Assert.Equal("MyPC", DnsPackets.ChooseHostname(new[] { "MyPC._workstation._tcp.local" }));
    }

    private static byte[] NodeStatus(params (string Name, byte Suffix, bool Group)[] names)
    {
        var packet = new List<byte> { 0x11, 0x11, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
        packet.AddRange(new byte[] { 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 });
        var dataLength = 1 + names.Length * 18;
        packet.Add(0x00);
        packet.Add((byte)dataLength);
        packet.Add((byte)names.Length);
        foreach (var (name, suffix, group) in names)
        {
            var raw = Encoding.ASCII.GetBytes(name.PadRight(15));
            packet.AddRange(raw.Take(15));
            packet.Add(suffix);
            packet.Add((byte)(group ? 0x80 : 0x04));
            packet.Add(0x00);
        }

        return packet.ToArray();
    }
}

public class OuiAndExportTests
{
    [Fact]
    public void Looks_up_known_vendors_and_local_addresses()
    {
        Assert.True(OuiDatabase.Count > 1000);
        Assert.Equal("Apple, Inc.", OuiDatabase.Lookup("3C:22:FB:10:20:30"));
        Assert.Equal("Cisco Systems, Inc", OuiDatabase.Lookup("00-00-0C-11-22-33"));
        Assert.Equal("VMware, Inc.", OuiDatabase.Lookup("000c29aabbcc"));
        Assert.Equal("Raspberry Pi Foundation", OuiDatabase.Lookup("B8:27:EB:00:00:01"));
        Assert.Equal("Locally administered", OuiDatabase.Lookup("02:42:AC:11:00:02"));
        Assert.Null(OuiDatabase.Lookup(null));
        Assert.Null(OuiDatabase.Lookup("not-a-mac"));
    }

    [Fact]
    public void Exports_csv_and_json()
    {
        var host = new HostResult
        {
            Address = IPAddress.Parse("10.1.2.3"),
            DnsName = "lab.example",
            Vendor = "Acme, \"Lab\"",
            LatencyMs = 4
        };
        host.Ports.Add(new OpenPort(445, "microsoft-ds", null, false));
        host.Ports.Add(new OpenPort(22, "ssh", "SSH-2.0-OpenSSH", true));

        var csv = ResultExporter.ToCsv(new[] { host });
        Assert.StartsWith(ResultColumns.CsvHeaderLine, csv);
        Assert.StartsWith("IP Address,Hostname,", csv);
        Assert.Contains("MAC Address", ResultColumns.CsvHeaderLine);
        Assert.Contains("Latency (ms)", ResultColumns.CsvHeaderLine);
        Assert.Contains("Open Ports", ResultColumns.CsvHeaderLine);
        Assert.All(ResultColumns.Grid, header => Assert.False(string.IsNullOrWhiteSpace(header)));
        Assert.Equal("IP Address", ResultColumns.Grid[0]);
        Assert.Equal("Hostname", ResultColumns.Grid[1]);
        Assert.Contains("\"Acme, \"\"Lab\"\"\"", csv);
        Assert.Contains("22/ssh", csv);
        Assert.Contains("445/microsoft-ds", csv);

        var json = ResultExporter.ToJson(new[] { host });
        Assert.Contains("\"IP Address\": \"10.1.2.3\"", json);
        Assert.Contains("\"Hostname\"", json);
        Assert.Contains("\"Open Ports\"", json);
        Assert.Contains("microsoft-ds", json);
        Assert.Contains("\"ssh\": true", json);
        Assert.Contains("\"smb\": true", json);
    }

    [Fact]
    public void Service_names_follow_the_port_and_the_banner()
    {
        Assert.Equal("https", ServiceNames.ForPort(443));
        Assert.Equal("ms-wbt-server", ServiceNames.ForPort(3389));
        Assert.Equal("ssh", ServiceNames.Resolve(2222, "SSH-2.0-OpenSSH_9.0"));
        Assert.True(BannerClassifier.IsSsh("  SSH-2.0-Test"));
        Assert.False(BannerClassifier.IsSsh("HTTP/1.1 200 OK"));
        Assert.True(new OpenPort(22, "ssh", null, false).IsSsh);
        Assert.True(new OpenPort(3389, "ms-wbt-server", null, false).IsRdp);
        Assert.True(new OpenPort(139, "netbios-ssn", null, false).IsSmb);
        Assert.False(new OpenPort(80, "http", null, false).IsSsh);
    }
}

public class LocalSubnetTests
{
    [Fact]
    public void Converts_masks_and_builds_cidr()
    {
        Assert.Equal(24, LocalSubnet.MaskToPrefix(IPAddress.Parse("255.255.255.0")));
        Assert.Equal(25, LocalSubnet.MaskToPrefix(IPAddress.Parse("255.255.255.128")));
        Assert.Equal(8, LocalSubnet.MaskToPrefix(IPAddress.Parse("255.0.0.0")));
        Assert.Equal(-1, LocalSubnet.MaskToPrefix(IPAddress.Parse("255.255.0.255")));
        Assert.Equal("192.168.1.0/24", LocalSubnet.ToCidr(IPAddress.Parse("192.168.1.42"), IPAddress.Parse("255.255.255.0")));
        Assert.True(LocalSubnet.Contains(IPAddress.Parse("192.168.1.0"), 24, IPAddress.Parse("192.168.1.42")));
        Assert.False(LocalSubnet.Contains(IPAddress.Parse("192.168.1.0"), 24, IPAddress.Parse("192.168.2.1")));
    }

    [Fact]
    public void Prefers_a_routable_private_adapter_over_apipa()
    {
        var ethernet = LocalSubnet.Rank(IPAddress.Parse("192.168.1.5"), NetworkInterfaceType.Ethernet, hasGateway: true);
        var apipa = LocalSubnet.Rank(IPAddress.Parse("169.254.1.5"), NetworkInterfaceType.Ethernet, hasGateway: false);
        Assert.True(ethernet < apipa);
        Assert.True(LocalSubnet.IsPrivate(IPAddress.Parse("10.1.1.1")));
        Assert.False(LocalSubnet.IsPrivate(IPAddress.Parse("8.8.8.8")));
        Assert.Null(Record.Exception(() => LocalSubnet.DetectCidr()));
    }

    [Fact]
    public void Parses_the_linux_arp_table()
    {
        const string table = """
            IP address       HW type     Flags       HW address            Mask     Device
            192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0
            192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        eth0
            """;
        Assert.Equal("00:11:22:33:44:55", ArpLookup.ParseProcNetArp(table, IPAddress.Parse("192.168.1.1")));
        Assert.Null(ArpLookup.ParseProcNetArp(table, IPAddress.Parse("192.168.1.2")));
    }
}

public class DemoCatalogTests
{
    [Fact]
    public void Demo_hosts_are_fictional_and_cover_the_screenshot_columns()
    {
        var sample = DemoCatalog.Create();
        Assert.InRange(sample.Hosts.Count, 6, 10);
        Assert.Contains(sample.Hosts, host => host.Hostname == "DESKTOP-DEMO01");
        Assert.Contains(sample.Hosts, host => host.Hostname == "nas-demo");
        Assert.Contains(sample.Hosts, host => host.Hostname == "printer-demo");
        Assert.All(sample.Hosts, host => Assert.True(LocalSubnet.Contains(IPAddress.Parse("192.168.1.0"), 24, host.Address)));

        var desktop = sample.Hosts.Single(host => host.Hostname == "DESKTOP-DEMO01");
        var numbers = desktop.CopyPorts().Select(port => port.Number).ToArray();
        Assert.Contains(22, numbers);
        Assert.Contains(80, numbers);
        Assert.Contains(443, numbers);
        Assert.Contains(445, numbers);
        Assert.Contains(3389, numbers);
        Assert.Contains(desktop.CopyPorts(), port => port.IsSsh);
        Assert.Contains(desktop.CopyPorts(), port => port.IsRdp);
        Assert.Contains(desktop.CopyPorts(), port => port.IsSmb);
        Assert.NotNull(desktop.LatencyMs);

        var shares = sample.Shares[desktop.Address.ToString()];
        Assert.Equal(SmbStatus.Ok, shares.Status);
        Assert.Contains(shares.Shares, share => share.Kind == ShareKind.Disk && !share.IsAdmin);
        var csv = ResultExporter.ToCsv(sample.Hosts);
        Assert.StartsWith("IP Address,Hostname,", csv);
        Assert.Contains("DESKTOP-DEMO01", csv);
    }
}
