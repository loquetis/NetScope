using System.Text;

namespace NetScope.Core;

public static class NetBiosNames
{
    public static byte[] BuildNodeStatusQuery(ushort transactionId)
    {
        var encoded = EncodeName("*");
        var packet = new byte[12 + 1 + encoded.Length + 1 + 4];
        packet[0] = (byte)(transactionId >> 8);
        packet[1] = (byte)transactionId;
        packet[5] = 1;
        packet[12] = 32;
        Encoding.ASCII.GetBytes(encoded).CopyTo(packet, 13);
        var offset = 13 + encoded.Length;
        packet[offset] = 0;
        packet[offset + 2] = 0x21;
        packet[offset + 4] = 0x01;
        return packet;
    }

    public static string EncodeName(string name)
    {
        Span<byte> raw = stackalloc byte[16];
        raw.Clear();
        if (name == "*")
        {
            raw[0] = 0x2A;
        }
        else
        {
            var bytes = Encoding.ASCII.GetBytes(name);
            bytes.AsSpan(0, Math.Min(16, bytes.Length)).CopyTo(raw);
        }

        var chars = new char[32];
        for (var i = 0; i < 16; i++)
        {
            chars[i * 2] = (char)(((raw[i] >> 4) & 0x0F) + 'A');
            chars[i * 2 + 1] = (char)((raw[i] & 0x0F) + 'A');
        }

        return new string(chars);
    }

    public static string? ParseNodeStatusResponse(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 16)
            return null;

        var questions = DnsPackets.ReadU16(packet, 4);
        var answers = DnsPackets.ReadU16(packet, 6);
        var offset = 12;
        for (var i = 0; i < questions && offset < packet.Length; i++)
        {
            DnsPackets.ReadName(packet, offset, out offset);
            offset += 4;
        }

        string? workstation = null;
        string? server = null;
        string? anyUnique = null;
        for (var i = 0; i < answers && offset + 12 < packet.Length; i++)
        {
            DnsPackets.ReadName(packet, offset, out offset);
            if (offset + 10 > packet.Length)
                break;
            var type = DnsPackets.ReadU16(packet, offset);
            offset += 8;
            var dataLength = DnsPackets.ReadU16(packet, offset);
            offset += 2;
            if (offset + dataLength > packet.Length)
                break;
            if (type == 0x0021 && dataLength >= 1)
            {
                var count = packet[offset];
                var cursor = offset + 1;
                var end = offset + dataLength;
                for (var nameIndex = 0; nameIndex < count; nameIndex++)
                {
                    if (cursor + 18 > end)
                        break;
                    var name = Encoding.ASCII.GetString(packet.Slice(cursor, 15)).Trim().TrimEnd('\0');
                    var suffix = packet[cursor + 15];
                    var flags = DnsPackets.ReadU16(packet, cursor + 16);
                    cursor += 18;
                    var group = (flags & 0x8000) != 0;
                    if (group || string.IsNullOrWhiteSpace(name))
                        continue;
                    anyUnique ??= name;
                    if (suffix == 0x00)
                        workstation ??= name;
                    if (suffix == 0x20)
                        server ??= name;
                }
            }

            offset += dataLength;
        }

        return workstation ?? server ?? anyUnique;
    }
}
