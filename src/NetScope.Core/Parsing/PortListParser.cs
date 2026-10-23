using System.Globalization;

namespace NetScope.Core;

public static class PortListParser
{
    public static IReadOnlyList<int> Parse(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            throw new FormatException("Enter at least one port or range, such as 22,80,443 or 8000-8010.");

        var set = new SortedSet<int>();
        var parts = text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0)
            throw new FormatException("Enter at least one port or range, such as 22,80,443 or 8000-8010.");

        foreach (var part in parts)
        {
            var bounds = part.Split('-', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (bounds.Length == 1)
            {
                set.Add(ParsePort(bounds[0]));
            }
            else if (bounds.Length == 2)
            {
                var start = ParsePort(bounds[0]);
                var end = ParsePort(bounds[1]);
                if (start > end)
                    throw new FormatException($"Port range '{part}' is reversed.");
                for (var port = start; port <= end; port++)
                    set.Add(port);
            }
            else
            {
                throw new FormatException($"'{part}' is not a port or range.");
            }
        }

        if (set.Count == 0)
            throw new FormatException("Enter at least one port or range, such as 22,80,443 or 8000-8010.");
        return set.ToArray();
    }

    public static int ParsePort(string text)
    {
        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port < 1 || port > 65535)
            throw new FormatException($"'{text}' is not a valid TCP port (1-65535).");
        return port;
    }

    public static IReadOnlyList<int> ForMode(PortSelectionMode mode, string? custom)
    {
        return mode switch
        {
            PortSelectionMode.Common => CommonPorts.Top100,
            PortSelectionMode.All => AllPorts(),
            PortSelectionMode.Custom => Parse(custom ?? ""),
            _ => throw new ArgumentOutOfRangeException(nameof(mode))
        };
    }

    public static int[] AllPorts()
    {
        var ports = new int[65535];
        for (var i = 0; i < ports.Length; i++)
            ports[i] = i + 1;
        return ports;
    }
}
