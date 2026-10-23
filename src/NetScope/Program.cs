using NetScope.Core;

namespace NetScope;

static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, args) => Report(args.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex)
                Report(ex);
        };
        var demo = args.Any(arg => string.Equals(arg, DemoCatalog.Flag, StringComparison.OrdinalIgnoreCase));
        Application.Run(new MainForm(demo));
    }

    private static void Report(Exception exception)
    {
        try
        {
            MessageBox.Show(exception.Message, "NetScope", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch
        {
            // The process is already failing. Avoid a second crash from the dialog.
        }
    }
}
