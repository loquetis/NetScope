using System.Net;
using System.Net.Sockets;

namespace NetScope.Core;

public static class NameResolver
{
    public static async Task<string?> ReverseDnsAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken)
    {
        try
        {
            var lookup = Dns.GetHostEntryAsync(address);
            var finished = await Task.WhenAny(lookup, Task.Delay(timeoutMs, cancellationToken)).ConfigureAwait(false);
            if (finished != lookup)
                return null;
            var entry = await lookup.ConfigureAwait(false);
            var name = entry.HostName;
            if (string.IsNullOrWhiteSpace(name))
                return null;
            if (string.Equals(name, address.ToString(), StringComparison.OrdinalIgnoreCase))
                return null;
            return name.TrimEnd('.');
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    public static Task<string?> NetBiosAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken)
    {
        var query = NetBiosNames.BuildNodeStatusQuery((ushort)Random.Shared.Next(1, ushort.MaxValue));
        return QueryNameAsync(address, 137, query, timeoutMs, cancellationToken, NetBiosNames.ParseNodeStatusResponse);
    }

    public static async Task<string?> MulticastNameAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken)
    {
        var query = DnsPackets.BuildPtrQuery(DnsPackets.ReverseArpa(address), (ushort)Random.Shared.Next(1, ushort.MaxValue));
        var mdns = QueryNameAsync(address, 5353, query, timeoutMs, cancellationToken, ParseMdns);
        var llmnr = QueryNameAsync(address, 5355, query, timeoutMs, cancellationToken, ParseMdns);
        await Task.WhenAll(mdns, llmnr).ConfigureAwait(false);
        return mdns.Result ?? llmnr.Result;
    }

    private static string? ParseMdns(ReadOnlySpan<byte> packet)
        => DnsPackets.ChooseHostname(DnsPackets.ReadPtrAnswers(packet));

    private static async Task<string?> QueryNameAsync(
        IPAddress address,
        int port,
        byte[] query,
        int timeoutMs,
        CancellationToken cancellationToken,
        NameParser parse)
    {
        try
        {
            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            var remote = new IPEndPoint(address, port);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(timeoutMs);
            await udp.SendToAsync(query, SocketFlags.None, remote, timeout.Token).ConfigureAwait(false);
            var buffer = new byte[2048];
            var result = await udp.ReceiveFromAsync(buffer, SocketFlags.None, remote, timeout.Token).ConfigureAwait(false);
            return parse(buffer.AsSpan(0, result.ReceivedBytes));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private delegate string? NameParser(ReadOnlySpan<byte> packet);
}

public static class IdentityResolver
{
    public static async Task EnrichAsync(HostResult host, CancellationToken cancellationToken)
    {
        var dns = NameResolver.ReverseDnsAsync(host.Address, ScanLimits.NameTimeoutMs, cancellationToken);
        var netbios = NameResolver.NetBiosAsync(host.Address, ScanLimits.NameTimeoutMs, cancellationToken);
        var mdns = NameResolver.MulticastNameAsync(host.Address, ScanLimits.NameTimeoutMs, cancellationToken);
        var arp = ArpLookup.TryGetMacAsync(host.Address, cancellationToken);
        await Task.WhenAll(dns, netbios, mdns, arp).ConfigureAwait(false);
        host.DnsName = dns.Result;
        host.NetBiosName = netbios.Result;
        host.MdnsName = mdns.Result;
        host.MacAddress = arp.Result;
        if (!string.IsNullOrWhiteSpace(host.MacAddress))
            host.Vendor = OuiDatabase.Lookup(host.MacAddress);
    }
}
