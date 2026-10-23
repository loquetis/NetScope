using System.Text.Json;
using NetScope.Core;

namespace NetScope;

internal sealed class UserSettings
{
    public string LastSshUsername { get; set; } = "";
    public int Concurrency { get; set; } = ScanLimits.DefaultConcurrency;
    public int TimeoutMs { get; set; } = ScanLimits.DefaultTimeoutMs;
    public int PortMode { get; set; }
    public string CustomPorts { get; set; } = "22,80,443,445,3389,8080";
    public bool HideAdminShares { get; set; } = true;
    public bool OnlyOpenPorts { get; set; }
}

internal static class SettingsStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "NetScope",
        "settings.json");

    public static UserSettings Load()
    {
        try
        {
            if (!File.Exists(FilePath))
                return new UserSettings();
            var settings = JsonSerializer.Deserialize<UserSettings>(File.ReadAllText(FilePath)) ?? new UserSettings();
            settings.Concurrency = Math.Clamp(settings.Concurrency, ScanLimits.MinConcurrency, ScanLimits.MaxConcurrency);
            settings.TimeoutMs = Math.Clamp(settings.TimeoutMs, ScanLimits.MinTimeoutMs, ScanLimits.MaxTimeoutMs);
            settings.PortMode = Math.Clamp(settings.PortMode, 0, 2);
            settings.LastSshUsername ??= "";
            settings.CustomPorts ??= "";
            return settings;
        }
        catch
        {
            return new UserSettings();
        }
    }

    public static void Save(UserSettings settings)
    {
        try
        {
            var directory = Path.GetDirectoryName(FilePath)!;
            Directory.CreateDirectory(directory);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(settings, Json));
        }
        catch
        {
            // Settings are a convenience. A failed write should not block a scan.
        }
    }
}
