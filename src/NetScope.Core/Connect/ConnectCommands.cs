using System.Text.RegularExpressions;

namespace NetScope.Core;

public enum SshClientKind
{
    WindowsTerminal,
    ConsoleOpenSsh,
    Putty,
    Missing
}

public sealed record RdpLaunch(string FileName, string Arguments);

public sealed record SshLaunch(SshClientKind Kind, string FileName, string Arguments, string? Message);

public sealed record SshClientAvailability(bool HasWindowsTerminal, bool HasOpenSsh, string? OpenSshPath, string? PuttyPath)
{
    public static SshClientAvailability None { get; } = new(false, false, null, null);
}

public sealed record SshClientProbe(bool WindowsTerminalOnPath, bool OpenSshOnPath, string? OpenSshPath, string? PuttyPath);

public static class ConnectCommands
{
    public const string MissingSshMessage =
        "OpenSSH client (ssh.exe) was not found, and PuTTY is not installed. Install the Windows OpenSSH Client optional feature, or install PuTTY, then try again. NetScope never asks for or stores an SSH password.";

    private static readonly Regex SafeHostPattern = new(@"^[A-Za-z0-9._:-]+$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex SafeUserPattern = new(@"^[A-Za-z0-9._@\\-]+$", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static bool IsSafeHost(string? host)
        => !string.IsNullOrWhiteSpace(host) && SafeHostPattern.IsMatch(host);

    public static bool IsSafeUser(string user)
        => SafeUserPattern.IsMatch(user);

    public static string SelectHost(string? dns, string? netbios, string? mdns, string ip)
    {
        foreach (var candidate in new[] { dns, netbios, mdns })
        {
            if (string.IsNullOrWhiteSpace(candidate))
                continue;
            var trimmed = candidate.Trim().TrimEnd('.');
            if (IsSafeHost(trimmed))
                return trimmed;
        }

        EnsureHost(ip);
        return ip;
    }

    public static RdpLaunch BuildRdp(string host, int port)
    {
        EnsureHost(host);
        EnsurePort(port);
        return new RdpLaunch("mstsc.exe", $"/v:{host}:{port}");
    }

    public static SshLaunch BuildSsh(string? username, string host, int port, SshClientAvailability availability)
    {
        EnsureHost(host);
        EnsurePort(port);
        username = string.IsNullOrWhiteSpace(username) ? null : username.Trim();
        if (username != null && !IsSafeUser(username))
            throw new ArgumentException("Username contains characters that are not allowed in the SSH command.");

        var target = username == null ? host : $"{username}@{host}";
        if (availability.HasOpenSsh)
        {
            var ssh = string.IsNullOrWhiteSpace(availability.OpenSshPath) ? "ssh" : Quote(availability.OpenSshPath);
            var command = $"{ssh} {target} -p {port}";
            if (availability.HasWindowsTerminal)
                return new SshLaunch(SshClientKind.WindowsTerminal, "wt.exe", $"-- {command}", null);

            var arguments = $"/c start \"NetScope SSH\" cmd.exe /k {command}";
            return new SshLaunch(SshClientKind.ConsoleOpenSsh, "cmd.exe", arguments, null);
        }

        if (!string.IsNullOrWhiteSpace(availability.PuttyPath))
        {
            var arguments = username == null
                ? $"-ssh {host} -P {port}"
                : $"-ssh {host} -P {port} -l {username}";
            return new SshLaunch(SshClientKind.Putty, availability.PuttyPath, arguments, null);
        }

        return new SshLaunch(SshClientKind.Missing, "", "", MissingSshMessage);
    }

    public static SshClientAvailability FromProbe(SshClientProbe probe)
    {
        var sshPath = string.IsNullOrWhiteSpace(probe.OpenSshPath) ? null : probe.OpenSshPath;
        var ssh = sshPath != null || probe.OpenSshOnPath;
        if (ssh && sshPath == null)
            sshPath = "ssh";
        return new SshClientAvailability(
            HasWindowsTerminal: ssh && probe.WindowsTerminalOnPath,
            HasOpenSsh: ssh,
            OpenSshPath: ssh ? sshPath : null,
            PuttyPath: ssh || string.IsNullOrWhiteSpace(probe.PuttyPath) ? null : probe.PuttyPath);
    }

    public static SshClientProbe ProbeInstalledClients()
    {
        var sshPath = FindOnPath("ssh.exe");
        if (sshPath == null)
        {
            var systemSsh = Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh.exe");
            if (File.Exists(systemSsh))
                sshPath = systemSsh;
        }

        var windowsApps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "wt.exe");
        var terminal = ExistsOnPath("wt.exe") || File.Exists(windowsApps);
        return new SshClientProbe(terminal, sshPath != null, sshPath, FindPutty());
    }

    public static bool MstscExists()
        => File.Exists(Path.Combine(Environment.SystemDirectory, "mstsc.exe")) || ExistsOnPath("mstsc.exe");

    public static string? FindOnPath(string fileName, string? pathVariable = null)
    {
        pathVariable ??= Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(pathVariable))
            return null;
        foreach (var directory in pathVariable.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var full = Path.Combine(directory.Trim(), fileName);
                if (File.Exists(full))
                    return full;
            }
            catch (ArgumentException)
            {
                // Ignore a malformed PATH entry.
            }
        }

        return null;
    }

    public static string Quote(string path)
        => path.Contains(' ', StringComparison.Ordinal) ? $"\"{path}\"" : path;

    private static bool ExistsOnPath(string fileName) => FindOnPath(fileName) != null;

    private static string? FindPutty()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PuTTY", "putty.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "PuTTY", "putty.exe")
        };
        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
                return candidate;
        }

        return FindOnPath("putty.exe");
    }

    private static void EnsureHost(string host)
    {
        if (!IsSafeHost(host))
            throw new ArgumentException("Host contains characters that are not allowed in a command.", nameof(host));
    }

    private static void EnsurePort(int port)
    {
        if (port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(port), "Port must be between 1 and 65535.");
    }
}
