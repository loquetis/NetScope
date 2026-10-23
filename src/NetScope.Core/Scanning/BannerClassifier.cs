namespace NetScope.Core;

public static class BannerClassifier
{
    public static bool IsSsh(string? banner)
    {
        if (string.IsNullOrWhiteSpace(banner))
            return false;
        return banner.TrimStart().StartsWith("SSH-", StringComparison.OrdinalIgnoreCase);
    }

    public static string? Normalize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        var cleaned = new string(raw.Select(ch => char.IsControl(ch) && ch is not '\t' ? ' ' : ch).ToArray()).Trim();
        if (cleaned.Length == 0)
            return null;
        return cleaned.Length > 160 ? cleaned[..160] : cleaned;
    }
}
