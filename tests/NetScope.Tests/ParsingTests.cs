using System.Net;
using NetScope.Core;

namespace NetScope.Tests;

public class TargetParserTests
{
    [Fact]
    public void Cidr24_excludes_network_and_broadcast()
    {
        var hosts = TargetParser.Parse("192.168.1.0/24");
        Assert.Equal(254, hosts.Count);
        Assert.Equal("192.168.1.1", hosts[0].ToString());
        Assert.Equal("192.168.1.254", hosts[^1].ToString());
    }

    [Fact]
    public void Cidr_uses_the_network_when_host_bits_are_set()
    {
        var hosts = TargetParser.Parse("192.168.1.50/24");
        Assert.Equal(254, hosts.Count);
        Assert.Equal("192.168.1.1", hosts[0].ToString());
    }

    [Fact]
    public void Cidr30_and_32_and_31()
    {
        Assert.Equal(new[] { "10.0.0.1", "10.0.0.2" }, TargetParser.Parse("10.0.0.0/30").Select(ip => ip.ToString()));
        Assert.Equal("10.0.0.5", Assert.Single(TargetParser.Parse("10.0.0.5/32")).ToString());
        Assert.Equal(new[] { "192.168.1.0", "192.168.1.1" }, TargetParser.Parse("192.168.1.0/31").Select(ip => ip.ToString()));
    }

    [Fact]
    public void Cidr16_is_allowed_and_15_is_rejected()
    {
        Assert.Equal(65534, TargetParser.Parse("10.0.0.0/16").Count);
        var error = Assert.Throws<FormatException>(() => TargetParser.Parse("10.0.0.0/15"));
        Assert.Contains("65,536", error.Message);
    }

    [Theory]
    [InlineData("192.168.1.10-50", 41, "192.168.1.10", "192.168.1.50")]
    [InlineData("192.168.1.10-192.168.1.12", 3, "192.168.1.10", "192.168.1.12")]
    [InlineData("  10.0.0.8  ", 1, "10.0.0.8", "10.0.0.8")]
    [InlineData("10.1.1.0 / 30", 2, "10.1.1.1", "10.1.1.2")]
    public void Parses_ranges_and_single_addresses(string text, int count, string first, string last)
    {
        var hosts = TargetParser.Parse(text);
        Assert.Equal(count, hosts.Count);
        Assert.Equal(first, hosts[0].ToString());
        Assert.Equal(last, hosts[^1].ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-an-ip")]
    [InlineData("192.168.1.256")]
    [InlineData("192.168.1.0/33")]
    [InlineData("192.168.1.50-10")]
    [InlineData("10.0.0.5-10.0.0.1")]
    [InlineData("2001:db8::1")]
    public void Rejects_invalid_targets(string text)
    {
        Assert.Throws<FormatException>(() => TargetParser.Parse(text));
    }
}

public class PortListParserTests
{
    [Fact]
    public void Parses_lists_and_ranges_without_duplicates()
    {
        var ports = PortListParser.Parse("80, 443, 8000-8002, 80");
        Assert.Equal(new[] { 80, 443, 8000, 8001, 8002 }, ports);
    }

    [Fact]
    public void All_ports_cover_1_through_65535()
    {
        var ports = PortListParser.ForMode(PortSelectionMode.All, null);
        Assert.Equal(65535, ports.Count);
        Assert.Equal(1, ports[0]);
        Assert.Equal(65535, ports[^1]);
    }

    [Fact]
    public void Common_ports_are_the_top_100_and_include_the_usual_services()
    {
        var ports = PortListParser.ForMode(PortSelectionMode.Common, null);
        Assert.Equal(100, ports.Count);
        Assert.Equal(ports.Count, ports.Distinct().Count());
        foreach (var port in new[] { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080 })
            Assert.Contains(port, ports);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("80-70")]
    [InlineData("http")]
    public void Rejects_invalid_port_lists(string text)
    {
        Assert.Throws<FormatException>(() => PortListParser.Parse(text));
    }
}
