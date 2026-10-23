using System.Runtime.InteropServices;
using System.Text;

namespace NetScope;

internal static class WindowsCredentialPrompt
{
    public static bool TryPrompt(IWin32Window owner, string host, out string username, out string password)
    {
        username = "";
        password = "";
        if (!OperatingSystem.IsWindows())
            return false;

        var info = new CredUiInfo
        {
            Size = Marshal.SizeOf<CredUiInfo>(),
            Parent = owner.Handle,
            Caption = "NetScope SMB credentials",
            Message = $"Enter credentials for \\\\{host}. NetScope does not store this password.",
            Banner = IntPtr.Zero
        };

        uint package = 0;
        var save = false;
        var result = CredUIPromptForWindowsCredentials(
            ref info,
            0,
            ref package,
            IntPtr.Zero,
            0,
            out var buffer,
            out var bufferSize,
            ref save,
            0);
        if (result == 1223)
            return false;
        if (result != 0)
            throw new InvalidOperationException($"Windows could not show the credential dialog (error {result}).");

        try
        {
            if (!TryUnpack(buffer, bufferSize, out username, out password))
                throw new InvalidOperationException("Windows returned credentials that NetScope could not read.");
            return true;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                CoTaskMemFree(buffer);
        }
    }

    private static bool TryUnpack(IntPtr buffer, uint bufferSize, out string username, out string password)
    {
        username = "";
        password = "";
        var user = new StringBuilder(256);
        var domain = new StringBuilder(256);
        var pass = new StringBuilder(256);
        var userLen = user.Capacity;
        var domainLen = domain.Capacity;
        var passLen = pass.Capacity;
        if (!CredUnPackAuthenticationBuffer(0, buffer, bufferSize, user, ref userLen, domain, ref domainLen, pass, ref passLen))
        {
            user = new StringBuilder(Math.Max(userLen, 1));
            domain = new StringBuilder(Math.Max(domainLen, 1));
            pass = new StringBuilder(Math.Max(passLen, 1));
            userLen = user.Capacity;
            domainLen = domain.Capacity;
            passLen = pass.Capacity;
            if (!CredUnPackAuthenticationBuffer(0, buffer, bufferSize, user, ref userLen, domain, ref domainLen, pass, ref passLen))
                return false;
        }

        var userText = user.ToString();
        var domainText = domain.ToString();
        password = pass.ToString();
        username = string.IsNullOrEmpty(domainText) || userText.Contains('\\', StringComparison.Ordinal)
            ? userText
            : $"{domainText}\\{userText}";
        Clear(user);
        Clear(domain);
        Clear(pass);
        return true;
    }

    private static void Clear(StringBuilder builder)
    {
        for (var i = 0; i < builder.Length; i++)
            builder[i] = '\0';
        builder.Clear();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CredUiInfo
    {
        public int Size;
        public IntPtr Parent;
        public string Message;
        public string Caption;
        public IntPtr Banner;
    }

    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    private static extern int CredUIPromptForWindowsCredentials(
        ref CredUiInfo info,
        uint authError,
        ref uint authPackage,
        IntPtr inAuthBuffer,
        uint inAuthBufferSize,
        out IntPtr outAuthBuffer,
        out uint outAuthBufferSize,
        ref bool save,
        uint flags);

    [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredUnPackAuthenticationBuffer(
        uint flags,
        IntPtr authBuffer,
        uint authBufferSize,
        StringBuilder userName,
        ref int maxUserName,
        StringBuilder domainName,
        ref int maxDomainName,
        StringBuilder password,
        ref int maxPassword);

    [DllImport("ole32.dll")]
    private static extern void CoTaskMemFree(IntPtr pointer);
}
