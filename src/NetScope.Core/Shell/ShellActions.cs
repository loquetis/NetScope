namespace NetScope.Core;

public static class ShellActions
{
    public static string BuildExplorerArguments(string unc)
    {
        if (string.IsNullOrWhiteSpace(unc) || unc.Contains('"', StringComparison.Ordinal))
            throw new ArgumentException("UNC path is not valid.", nameof(unc));
        return unc.Contains(' ', StringComparison.Ordinal) ? $"\"{unc}\"" : unc;
    }
}
