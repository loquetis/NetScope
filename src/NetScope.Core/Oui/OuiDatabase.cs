using System.Text;

namespace NetScope.Core;

public static class OuiDatabase
{
    private static readonly Lazy<Dictionary<string, string>> Entries = new(Load);

    public static int Count => Entries.Value.Count;

    public static void Warmup() => _ = Entries.Value;

    public static string? Lookup(string? mac)
    {
        if (!MacAddress.TryParse(mac, out var bytes))
            return null;
        if (MacAddress.IsLocallyAdministered(bytes))
            return "Locally administered";

        var hex = Convert.ToHexString(bytes);
        var map = Entries.Value;
        for (var length = hex.Length; length >= 6; length--)
        {
            if (map.TryGetValue(hex[..length], out var vendor))
                return vendor;
        }

        return null;
    }

    private static Dictionary<string, string> Load()
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        using var stream = typeof(OuiDatabase).Assembly.GetManifestResourceStream("NetScope.Core.oui.txt")
            ?? throw new InvalidOperationException("The embedded OUI database is missing.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        while (reader.ReadLine() is { } line)
        {
            if (line.Length == 0 || line[0] == '#')
                continue;
            var split = line.IndexOf('\t');
            if (split <= 0 || split >= line.Length - 1)
                continue;
            map.TryAdd(line[..split].Trim().ToUpperInvariant(), line[(split + 1)..].Trim());
        }

        return map;
    }
}
