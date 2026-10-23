namespace NetScope.Core;

public enum ShareKind
{
    Disk,
    Printer,
    Device,
    Ipc,
    Unknown
}

public enum SmbStatus
{
    Ok,
    AccessDenied,
    CredentialConflict,
    TimedOut,
    Failed
}

public sealed record SmbShare(string Name, ShareKind Kind, string Remark, bool IsAdmin)
{
    public string KindLabel => Kind switch
    {
        ShareKind.Disk => "Disk",
        ShareKind.Printer => "Printer",
        ShareKind.Device => "Device",
        ShareKind.Ipc => "IPC",
        _ => "Unknown"
    };

    public static string FormatUnc(string host, string share)
    {
        if (!ConnectCommands.IsSafeHost(host))
            throw new ArgumentException("Host is not safe to use in a UNC path.", nameof(host));
        if (string.IsNullOrWhiteSpace(share) || share.IndexOfAny(['\\', '/', ':', '*', '?', '"', '<', '>', '|']) >= 0)
            throw new ArgumentException("Share name contains characters that cannot be opened.", nameof(share));
        return $@"\\{host}\{share}";
    }
}

public static class SmbShareClassifier
{
    public const uint SpecialMask = 0x80000000;

    public static bool IsAdmin(string name, uint rawType)
    {
        if ((rawType & SpecialMask) != 0)
            return true;
        return name.EndsWith("$", StringComparison.Ordinal);
    }

    public static ShareKind GetKind(uint rawType)
    {
        return (rawType & 0x0FFFFFFF) switch
        {
            0 => ShareKind.Disk,
            1 => ShareKind.Printer,
            2 => ShareKind.Device,
            3 => ShareKind.Ipc,
            _ => ShareKind.Unknown
        };
    }

    public static SmbShare Create(string name, uint rawType, string? remark)
        => new(name, GetKind(rawType), remark?.Trim() ?? "", IsAdmin(name, rawType));

    public static IReadOnlyList<SmbShare> Filter(IEnumerable<SmbShare> shares, bool hideAdmin)
        => (hideAdmin ? shares.Where(share => !share.IsAdmin) : shares).ToArray();
}

public sealed record SmbEnumerationResult(SmbStatus Status, string Message, IReadOnlyList<SmbShare> Shares)
{
    public static SmbEnumerationResult Ok(IReadOnlyList<SmbShare> shares)
        => new(SmbStatus.Ok, shares.Count == 0 ? "No shares were returned." : $"{shares.Count} share(s).", shares);

    public static SmbEnumerationResult Denied()
        => new(
            SmbStatus.AccessDenied,
            "Access denied. NetScope used your current Windows sign-in and did not store a password. Retry with different credentials if you have an account on this host.",
            Array.Empty<SmbShare>());

    public static SmbEnumerationResult Conflict()
        => new(
            SmbStatus.CredentialConflict,
            "Windows already has a connection to this host with different credentials. Disconnect the existing connection to this host and try again.",
            Array.Empty<SmbShare>());

    public static SmbEnumerationResult Timeout()
        => new(
            SmbStatus.TimedOut,
            "Timed out waiting for SMB. The host may be filtering the connection or is slow to respond.",
            Array.Empty<SmbShare>());

    public static SmbEnumerationResult Fail(string message)
        => new(SmbStatus.Failed, message, Array.Empty<SmbShare>());
}
