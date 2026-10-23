using NetScope.Core;

namespace NetScope.Tests;

public class ConnectCommandTests
{
    private static SshClientAvailability Terminal { get; } = new(true, true, "ssh", null);
    private static SshClientAvailability Console { get; } = new(false, true, "ssh", null);

    [Fact]
    public void Rdp_launches_mstsc_with_host_and_port()
    {
        var launch = ConnectCommands.BuildRdp("192.168.1.20", 3389);
        Assert.Equal("mstsc.exe", launch.FileName);
        Assert.Equal("/v:192.168.1.20:3389", launch.Arguments);
    }

    [Fact]
    public void Ssh_uses_windows_terminal_when_it_is_available()
    {
        var launch = ConnectCommands.BuildSsh("alice", "10.0.0.5", 22, Terminal);
        Assert.Equal(SshClientKind.WindowsTerminal, launch.Kind);
        Assert.Equal("wt.exe", launch.FileName);
        Assert.Equal("-- ssh alice@10.0.0.5 -p 22", launch.Arguments);
        Assert.DoesNotContain("-pw", launch.Arguments, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Ssh_without_a_username_omits_the_user()
    {
        var launch = ConnectCommands.BuildSsh("  ", "10.0.0.8", 2222, Terminal);
        Assert.Equal("-- ssh 10.0.0.8 -p 2222", launch.Arguments);
    }

    [Fact]
    public void Ssh_falls_back_to_a_new_console()
    {
        var launch = ConnectCommands.BuildSsh("bob", "host.local", 22, Console);
        Assert.Equal(SshClientKind.ConsoleOpenSsh, launch.Kind);
        Assert.Equal("cmd.exe", launch.FileName);
        Assert.Equal("/c start \"NetScope SSH\" cmd.exe /k ssh bob@host.local -p 22", launch.Arguments);
    }

    [Fact]
    public void Ssh_uses_putty_when_openssh_is_missing()
    {
        var availability = new SshClientAvailability(false, false, null, @"C:\Program Files\PuTTY\putty.exe");
        var launch = ConnectCommands.BuildSsh("carol", "10.1.1.1", 22, availability);
        Assert.Equal(SshClientKind.Putty, launch.Kind);
        Assert.Equal(@"C:\Program Files\PuTTY\putty.exe", launch.FileName);
        Assert.Equal("-ssh 10.1.1.1 -P 22 -l carol", launch.Arguments);
        Assert.DoesNotContain("password", launch.Arguments, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Ssh_explains_when_no_client_is_installed()
    {
        var launch = ConnectCommands.BuildSsh(null, "10.0.0.1", 22, SshClientAvailability.None);
        Assert.Equal(SshClientKind.Missing, launch.Kind);
        Assert.Contains("OpenSSH", launch.Message);
        Assert.Contains("PuTTY", launch.Message);
        Assert.Contains("never", launch.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Unsafe_username_or_host_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => ConnectCommands.BuildSsh("alice&calc", "10.0.0.1", 22, Terminal));
        Assert.Throws<ArgumentException>(() => ConnectCommands.BuildRdp("10.0.0.1;calc", 3389));
    }

    [Fact]
    public void SelectHost_prefers_a_safe_dns_name()
    {
        Assert.Equal("server.local", ConnectCommands.SelectHost("server.local", "SERVER", "pc.local", "10.0.0.5"));
        Assert.Equal("SERVER", ConnectCommands.SelectHost("bad name", "SERVER", null, "10.0.0.5"));
        Assert.Equal("10.0.0.5", ConnectCommands.SelectHost(null, null, null, "10.0.0.5"));
    }

    [Fact]
    public void Probe_prefers_openssh_and_keeps_putty_as_fallback()
    {
        var both = ConnectCommands.FromProbe(new SshClientProbe(true, true, @"C:\Windows\System32\OpenSSH\ssh.exe", @"C:\putty.exe"));
        Assert.True(both.HasWindowsTerminal);
        Assert.True(both.HasOpenSsh);
        Assert.Null(both.PuttyPath);
        var ssh = ConnectCommands.BuildSsh("a", "10.0.0.2", 22, both);
        Assert.Equal("-- C:\\Windows\\System32\\OpenSSH\\ssh.exe a@10.0.0.2 -p 22", ssh.Arguments);

        var putty = ConnectCommands.FromProbe(new SshClientProbe(true, false, null, @"C:\Program Files\PuTTY\putty.exe"));
        Assert.False(putty.HasOpenSsh);
        Assert.False(putty.HasWindowsTerminal);
        Assert.Equal(@"C:\Program Files\PuTTY\putty.exe", putty.PuttyPath);
    }

    [Fact]
    public void Quotes_paths_that_contain_spaces()
    {
        Assert.Equal("\"C:\\Program Files\\OpenSSH\\ssh.exe\"", ConnectCommands.Quote(@"C:\Program Files\OpenSSH\ssh.exe"));
        Assert.Equal("ssh", ConnectCommands.Quote("ssh"));
    }

    [Fact]
    public void FindOnPath_returns_a_file_in_the_given_path()
    {
        var directory = Path.Combine(Path.GetTempPath(), "netscope-path-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var file = Path.Combine(directory, "ssh.exe");
        File.WriteAllText(file, "");
        try
        {
            Assert.Equal(file, ConnectCommands.FindOnPath("ssh.exe", directory));
            Assert.Null(ConnectCommands.FindOnPath("missing.exe", directory));
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }
}

public class SmbShareTests
{
    [Fact]
    public void Flags_admin_shares_by_type_bit_and_dollar_suffix()
    {
        Assert.True(SmbShareClassifier.IsAdmin("C$", 0x80000000));
        Assert.True(SmbShareClassifier.IsAdmin("IPC$", 0x80000003));
        Assert.True(SmbShareClassifier.IsAdmin("ADMIN$", 0));
        Assert.False(SmbShareClassifier.IsAdmin("Public", 0));
    }

    [Fact]
    public void Maps_share_kinds_and_hides_admin_shares()
    {
        Assert.Equal(ShareKind.Disk, SmbShareClassifier.GetKind(0));
        Assert.Equal(ShareKind.Printer, SmbShareClassifier.GetKind(1));
        Assert.Equal(ShareKind.Device, SmbShareClassifier.GetKind(2));
        Assert.Equal(ShareKind.Ipc, SmbShareClassifier.GetKind(3));
        Assert.Equal(ShareKind.Disk, SmbShareClassifier.GetKind(0x80000000));

        var shares = new[]
        {
            SmbShareClassifier.Create("Public", 0, "files"),
            SmbShareClassifier.Create("C$", 0x80000000, "Default share"),
            SmbShareClassifier.Create("IPC$", 0x80000003, "Remote IPC")
        };
        var visible = SmbShareClassifier.Filter(shares, hideAdmin: true);
        Assert.Equal("Public", Assert.Single(visible).Name);
        Assert.Equal(3, SmbShareClassifier.Filter(shares, hideAdmin: false).Count);
        Assert.Equal("Disk", shares[0].KindLabel);
        Assert.Equal("IPC", shares[2].KindLabel);
    }

    [Fact]
    public void Builds_unc_paths_and_explorer_arguments()
    {
        Assert.Equal(@"\\192.168.1.5\Public", SmbShare.FormatUnc("192.168.1.5", "Public"));
        Assert.Equal("\"\\\\server\\Shared Files\"", ShellActions.BuildExplorerArguments(SmbShare.FormatUnc("server", "Shared Files")));
        Assert.Throws<ArgumentException>(() => SmbShare.FormatUnc("192.168.1.5", "bad\\share"));
        Assert.Throws<ArgumentException>(() => SmbShare.FormatUnc("bad host", "Public"));
    }

    [Fact]
    public async Task Smb_enumeration_on_non_windows_explains_why()
    {
        if (OperatingSystem.IsWindows())
            return;
        var result = await WindowsSmb.EnumerateAsync("127.0.0.1", null, null, 1000, CancellationToken.None);
        Assert.Equal(SmbStatus.Failed, result.Status);
        Assert.Contains("Windows", result.Message);
        Assert.Empty(result.Shares);
    }
}
