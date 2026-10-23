using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace NetScope.Core;

public static class TargetParser
{
    public static IReadOnlyList<IPAddress> Parse(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            throw new FormatException("Enter a subnet, IP range, or single IP address.");

        text = Regex.Replace(text.Trim(), @"\s+", "");

        var cidr = Regex.Match(text, @"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$");
        if (cidr.Success)
        {
            var address = ParseIp(cidr.Groups[1].Value);
            if (!int.TryParse(cidr.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var prefix))
                throw new FormatException("CIDR prefix must be between 0 and 32.");
            return ExpandCidr(address, prefix);
        }

        var shortRange = Regex.Match(text, @"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$");
        if (shortRange.Success)
        {
            var prefix = shortRange.Groups[1].Value;
            var startOctet = ParseOctet(shortRange.Groups[2].Value, text);
            var endOctet = ParseOctet(shortRange.Groups[3].Value, text);
            if (startOctet > endOctet)
                throw new FormatException("The range start is higher than the end.");
            var start = ParseIp($"{prefix}.{startOctet}");
            var end = ParseIp($"{prefix}.{endOctet}");
            return Enumerate(ToUInt(start), ToUInt(end));
        }

        var fullRange = Regex.Match(text, @"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$");
        if (fullRange.Success)
        {
            var start = ToUInt(ParseIp(fullRange.Groups[1].Value));
            var end = ToUInt(ParseIp(fullRange.Groups[2].Value));
            if (start > end)
                throw new FormatException("The range start is higher than the end.");
            return Enumerate(start, end);
        }

        if (Regex.IsMatch(text, @"^\d{1,3}(?:\.\d{1,3}){3}$"))
            return new[] { ParseIp(text) };

        throw new FormatException("Use CIDR (192.168.1.0/24), a range (192.168.1.10-50 or 192.168.1.10-192.168.1.50), or a single IP.");
    }

    public static uint ToUInt(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4)
            throw new FormatException("Only IPv4 addresses are supported.");
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    public static IPAddress FromUInt(uint value)
    {
        return new IPAddress(new[]
        {
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value
        });
    }

    public static IPAddress ParseIp(string text)
    {
        var parts = text.Split('.');
        if (parts.Length != 4)
            throw new FormatException($"'{text}' is not an IPv4 address.");
        var bytes = new byte[4];
        for (var i = 0; i < 4; i++)
            bytes[i] = (byte)ParseOctet(parts[i], text);
        return new IPAddress(bytes);
    }

    private static IReadOnlyList<IPAddress> ExpandCidr(IPAddress ip, int prefix)
    {
        if (prefix < 0 || prefix > 32)
            throw new FormatException("CIDR prefix must be between 0 and 32.");

        var address = ToUInt(ip);
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        var network = address & mask;
        var broadcast = network | ~mask;

        if (prefix >= 31)
            return Enumerate(network, broadcast);

        return Enumerate(network + 1, broadcast - 1);
    }

    private static IReadOnlyList<IPAddress> Enumerate(uint start, uint endInclusive)
    {
        var count = (ulong)endInclusive - start + 1;
        if (count > ScanLimits.MaxHosts)
        {
            throw new FormatException(
                $"That target expands to {count.ToString("N0", CultureInfo.InvariantCulture)} hosts. NetScope scans at most {ScanLimits.MaxHosts.ToString("N0", CultureInfo.InvariantCulture)} hosts at a time. Narrow the range.");
        }

        var list = new IPAddress[count];
        for (ulong i = 0; i < count; i++)
            list[i] = FromUInt((uint)(start + (uint)i));
        return list;
    }

    private static int ParseOctet(string text, string context)
    {
        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value < 0 || value > 255)
            throw new FormatException($"'{context}' is not an IPv4 address.");
        return value;
    }
}
