namespace NetScope.Core;

public static class MacAddress
{
    public static bool TryParse(string? text, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(text))
            return false;
        var hex = new string(text.Where(Uri.IsHexDigit).ToArray());
        if (hex.Length != 12)
            return false;
        try
        {
            bytes = Convert.FromHexString(hex);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static string Format(ReadOnlySpan<byte> bytes)
        => string.Join(":", bytes.ToArray().Select(b => b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture)));

    public static bool IsLocallyAdministered(ReadOnlySpan<byte> bytes)
        => bytes.Length > 0 && (bytes[0] & 0x02) != 0;
}
