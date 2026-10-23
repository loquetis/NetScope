using System.Net;
using System.Net.NetworkInformation;

namespace NetScope.Core;

public static class LocalSubnet
{
    public sealed record Candidate(IPAddress Address, IPAddress Mask, int Prefix, string Cidr, int Rank);

    public static string? DetectCidr()
    {
        return DetectCandidates().OrderBy(candidate => candidate.Rank).ThenBy(candidate => candidate.Cidr).FirstOrDefault()?.Cidr;
    }

    public static IReadOnlyList<Candidate> DetectCandidates()
    {
        var list = new List<Candidate>();
        NetworkInterface[] interfaces;
        try
        {
            interfaces = NetworkInterface.GetAllNetworkInterfaces();
        }
        catch
        {
            return list;
        }

        foreach (var nic in interfaces)
        {
            if (nic.OperationalStatus != OperationalStatus.Up)
                continue;
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                continue;

            IPInterfaceProperties properties;
            try
            {
                properties = nic.GetIPProperties();
            }
            catch
            {
                continue;
            }

            var hasGateway = properties.GatewayAddresses.Any(gateway =>
                gateway.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                !gateway.Address.Equals(IPAddress.Any));

            foreach (var unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    continue;
                if (IPAddress.IsLoopback(unicast.Address))
                    continue;
                var mask = unicast.IPv4Mask;
                if (mask == null)
                    continue;
                var prefix = MaskToPrefix(mask);
                if (prefix <= 0 || prefix > 32)
                    continue;
                var network = NetworkAddress(unicast.Address, mask);
                var cidr = $"{network}/{prefix}";
                list.Add(new Candidate(unicast.Address, mask, prefix, cidr, Rank(unicast.Address, nic.NetworkInterfaceType, hasGateway)));
            }
        }

        return list;
    }

    public static int Rank(IPAddress ip, NetworkInterfaceType type, bool hasGateway)
    {
        var rank = type == NetworkInterfaceType.Wireless80211 ? 10 : 0;
        if (hasGateway)
            rank -= 5;
        var bytes = ip.GetAddressBytes();
        if (bytes[0] == 169 && bytes[1] == 254)
            rank += 100;
        else if (!IsPrivate(ip))
            rank += 40;
        return rank;
    }

    public static bool IsPrivate(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4)
            return false;
        if (bytes[0] == 10)
            return true;
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            return true;
        return bytes[0] == 192 && bytes[1] == 168;
    }

    public static int MaskToPrefix(IPAddress mask)
    {
        var bytes = mask.GetAddressBytes();
        if (bytes.Length != 4)
            return -1;
        var prefix = 0;
        var zeroSeen = false;
        foreach (var value in bytes)
        {
            for (var bit = 7; bit >= 0; bit--)
            {
                var on = (value & (1 << bit)) != 0;
                if (on)
                {
                    if (zeroSeen)
                        return -1;
                    prefix++;
                }
                else
                {
                    zeroSeen = true;
                }
            }
        }

        return prefix;
    }

    public static IPAddress NetworkAddress(IPAddress address, IPAddress mask)
    {
        var ip = address.GetAddressBytes();
        var bits = mask.GetAddressBytes();
        var network = new byte[4];
        for (var i = 0; i < 4; i++)
            network[i] = (byte)(ip[i] & bits[i]);
        return new IPAddress(network);
    }

    public static string ToCidr(IPAddress address, IPAddress mask)
    {
        var prefix = MaskToPrefix(mask);
        if (prefix < 0)
            throw new FormatException("Subnet mask is not contiguous.");
        return $"{NetworkAddress(address, mask)}/{prefix}";
    }

    public static bool Contains(IPAddress network, int prefix, IPAddress address)
    {
        if (prefix < 0 || prefix > 32)
            return false;
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        return (TargetParser.ToUInt(address) & mask) == (TargetParser.ToUInt(network) & mask);
    }
}
