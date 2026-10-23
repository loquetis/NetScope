using System.Net;
using System.Runtime.InteropServices;

namespace NetScope.Core;

public static class ArpLookup
{
    public static async Task<string?> TryGetMacAsync(IPAddress address, CancellationToken cancellationToken)
    {
        try
        {
            var task = Task.Run(() => TryGetMac(address), cancellationToken);
            var finished = await Task.WhenAny(task, Task.Delay(800, cancellationToken)).ConfigureAwait(false);
            if (finished != task)
                return null;
            return await task.ConfigureAwait(false);
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

    public static string? TryGetMac(IPAddress address)
    {
        try
        {
            if (OperatingSystem.IsWindows())
                return WindowsSendArp(address);
            return ReadProcNetArp(address);
        }
        catch
        {
            return null;
        }
    }

    public static string? ParseProcNetArp(string text, IPAddress address)
    {
        foreach (var line in text.Split('\n'))
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4)
                continue;
            if (!IPAddress.TryParse(parts[0], out var parsed) || !parsed.Equals(address))
                continue;
            if (parts[2] == "0x0")
                continue;
            if (MacAddress.TryParse(parts[3], out var mac) && mac.Any(b => b != 0))
                return MacAddress.Format(mac);
        }

        return null;
    }

    private static string? ReadProcNetArp(IPAddress address)
    {
        const string path = "/proc/net/arp";
        if (!File.Exists(path))
            return null;
        return ParseProcNetArp(File.ReadAllText(path), address);
    }

    private static string? WindowsSendArp(IPAddress address)
    {
        var mac = new byte[8];
        var length = 6;
        var destination = BitConverter.ToUInt32(address.GetAddressBytes(), 0);
        var result = NativeMethods.SendARP(destination, 0, mac, ref length);
        if (result != 0 || length < 6)
            return null;
        if (mac.Take(6).All(b => b == 0))
            return null;
        return MacAddress.Format(mac.AsSpan(0, 6));
    }

    private static class NativeMethods
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(uint destIp, uint srcIp, byte[] mac, ref int physicalAddrLen);
    }
}
