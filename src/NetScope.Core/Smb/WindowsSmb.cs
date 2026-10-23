using System.Runtime.InteropServices;

namespace NetScope.Core;

public static class WindowsSmb
{
    public static async Task<SmbEnumerationResult> EnumerateAsync(
        string host,
        string? username,
        string? password,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        if (!ConnectCommands.IsSafeHost(host))
            return SmbEnumerationResult.Fail("The host name cannot be used in an SMB path.");
        if (!OperatingSystem.IsWindows())
        {
            return SmbEnumerationResult.Fail(
                "SMB share listing uses the Windows networking APIs and runs when NetScope is started on Windows.");
        }

        var work = Task.Run(() => Enumerate(host, username, password), cancellationToken);
        var finished = await Task.WhenAny(work, Task.Delay(timeoutMs, cancellationToken)).ConfigureAwait(false);
        if (finished != work)
            return SmbEnumerationResult.Timeout();
        return await work.ConfigureAwait(false);
    }

    private static SmbEnumerationResult Enumerate(string host, string? username, string? password)
    {
        var connected = false;
        var ipc = $@"\\{host}\IPC$";
        try
        {
            if (!string.IsNullOrEmpty(username))
            {
                var add = AddConnection(ipc, username, password);
                if (add == 1219)
                    return SmbEnumerationResult.Conflict();
                if (add != 0)
                    return MapError(add);
                connected = true;
            }

            var shares = new List<SmbShare>();
            var resume = 0;
            int result;
            do
            {
                result = NetShareEnum($@"\\{host}", 1, out var buffer, -1, out var entries, out _, ref resume);
                try
                {
                    if (result != 0 && result != 234)
                        return MapError(result);
                    var current = buffer;
                    var size = Marshal.SizeOf<ShareInfo1>();
                    for (var i = 0; i < entries; i++)
                    {
                        var info = Marshal.PtrToStructure<ShareInfo1>(current);
                        var name = Marshal.PtrToStringUni(info.NetName);
                        if (!string.IsNullOrWhiteSpace(name))
                        {
                            var remark = Marshal.PtrToStringUni(info.Remark);
                            shares.Add(SmbShareClassifier.Create(name, info.Type, remark));
                        }

                        current = IntPtr.Add(current, size);
                    }
                }
                finally
                {
                    if (buffer != IntPtr.Zero)
                        NetApiBufferFree(buffer);
                }
            }
            while (result == 234);

            var ordered = shares
                .OrderBy(share => share.IsAdmin)
                .ThenBy(share => share.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return SmbEnumerationResult.Ok(ordered);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return SmbEnumerationResult.Fail("Windows networking libraries (netapi32/mpr) are not available on this PC.");
        }
        finally
        {
            if (connected)
            {
                try { WNetCancelConnection2(ipc, 0, true); } catch { /* best-effort */ }
            }
        }
    }

    private static int AddConnection(string remote, string username, string? password)
    {
        var resource = new NetResource
        {
            Scope = 0,
            Type = 0,
            DisplayType = 0,
            Usage = 0,
            LocalName = null,
            RemoteName = remote,
            Comment = null,
            Provider = null
        };
        return WNetAddConnection2(ref resource, password, username, 0x00000004);
    }

    private static SmbEnumerationResult MapError(int code) => code switch
    {
        5 or 1326 => SmbEnumerationResult.Denied(),
        1219 => SmbEnumerationResult.Conflict(),
        53 or 67 => SmbEnumerationResult.Fail("Windows could not find that network path. The host may be offline or blocking SMB."),
        1231 or 1232 => SmbEnumerationResult.Fail("The network path to this host is unreachable."),
        1722 => SmbEnumerationResult.Fail("The RPC server is unavailable. SMB may be blocked by a firewall."),
        _ => SmbEnumerationResult.Fail($"SMB enumeration failed (Windows error {code}).")
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ShareInfo1
    {
        public IntPtr NetName;
        public uint Type;
        public IntPtr Remark;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NetResource
    {
        public int Scope;
        public int Type;
        public int DisplayType;
        public int Usage;
        public string? LocalName;
        public string RemoteName;
        public string? Comment;
        public string? Provider;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetShareEnum(
        string serverName,
        int level,
        out IntPtr buffer,
        int prefMaxLen,
        out int entriesRead,
        out int totalEntries,
        ref int resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetAddConnection2(ref NetResource resource, string? password, string? username, int flags);

    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    private static extern int WNetCancelConnection2(string name, int flags, bool force);
}
