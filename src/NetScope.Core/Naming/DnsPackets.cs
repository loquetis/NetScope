using System.Net;
using System.Text;

namespace NetScope.Core;

public static class DnsPackets
{
    public static byte[] EncodeName(string name)
    {
        var trimmed = name.Trim().TrimEnd('.');
        var labels = trimmed.Length == 0 ? Array.Empty<string>() : trimmed.Split('.');
        using var stream = new MemoryStream();
        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63)
                throw new FormatException($"DNS label '{label}' is invalid.");
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((byte)bytes.Length);
            stream.Write(bytes, 0, bytes.Length);
        }

        stream.WriteByte(0);
        return stream.ToArray();
    }

    public static string ReadName(ReadOnlySpan<byte> packet, int offset, out int next)
    {
        var labels = new List<string>();
        var guard = 0;
        var end = -1;
        var cursor = offset;
        while (cursor < packet.Length && guard++ < 64)
        {
            var length = packet[cursor];
            if (length == 0)
            {
                cursor++;
                break;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (cursor + 1 >= packet.Length)
                    break;
                var pointer = ((length & 0x3F) << 8) | packet[cursor + 1];
                if (end < 0)
                    end = cursor + 2;
                if (pointer >= packet.Length || pointer == cursor)
                    break;
                cursor = pointer;
                continue;
            }

            cursor++;
            if (cursor + length > packet.Length)
                break;
            labels.Add(Encoding.ASCII.GetString(packet.Slice(cursor, length)));
            cursor += length;
        }

        next = end < 0 ? cursor : end;
        return string.Join('.', labels);
    }

    public static byte[] BuildPtrQuery(string qname, ushort id)
    {
        var name = EncodeName(qname);
        var packet = new byte[12 + name.Length + 4];
        packet[0] = (byte)(id >> 8);
        packet[1] = (byte)id;
        packet[5] = 1;
        name.CopyTo(packet, 12);
        var offset = 12 + name.Length;
        packet[offset + 1] = 12;
        packet[offset + 3] = 1;
        return packet;
    }

    public static List<string> ReadPtrAnswers(ReadOnlySpan<byte> packet)
    {
        var names = new List<string>();
        if (packet.Length < 12)
            return names;
        var questions = ReadU16(packet, 4);
        var answers = ReadU16(packet, 6);
        var offset = 12;
        for (var i = 0; i < questions && offset < packet.Length; i++)
        {
            ReadName(packet, offset, out offset);
            offset += 4;
        }

        for (var i = 0; i < answers && offset + 10 < packet.Length; i++)
        {
            ReadName(packet, offset, out offset);
            if (offset + 10 > packet.Length)
                break;
            var type = ReadU16(packet, offset);
            offset += 8;
            var dataLength = ReadU16(packet, offset);
            offset += 2;
            if (offset + dataLength > packet.Length)
                break;
            if (type == 12 && dataLength > 0)
            {
                var ptr = ReadName(packet, offset, out _);
                if (!string.IsNullOrWhiteSpace(ptr))
                    names.Add(ptr);
            }

            offset += dataLength;
        }

        return names;
    }

    public static string ReverseArpa(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}.in-addr.arpa";
    }

    public static string? ChooseHostname(IEnumerable<string> names)
    {
        foreach (var raw in names)
        {
            var host = raw.Trim().TrimEnd('.');
            if (host.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase))
                continue;
            var cut = host.IndexOf("._", StringComparison.Ordinal);
            if (cut > 0)
                host = host[..cut];
            if (host.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
                host = host[..^".local".Length];
            host = host.Trim().TrimEnd('.');
            if (host.Length > 0)
                return host;
        }

        return null;
    }

    public static ushort ReadU16(ReadOnlySpan<byte> packet, int offset)
        => (ushort)((packet[offset] << 8) | packet[offset + 1]);
}
