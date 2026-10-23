namespace NetScope;

internal static class Theme
{
    public static readonly Color Navy = Color.FromArgb(15, 39, 68);
    public static readonly Color Accent = Color.FromArgb(15, 118, 110);
    public static readonly Color AccentDark = Color.FromArgb(17, 94, 89);
    public static readonly Color Bg = Color.FromArgb(244, 246, 248);
    public static readonly Color Card = Color.White;
    public static readonly Color Text = Color.FromArgb(23, 32, 46);
    public static readonly Color Muted = Color.FromArgb(90, 102, 118);
    public static readonly Color Line = Color.FromArgb(220, 226, 232);
    public static readonly Color WarnBg = Color.FromArgb(255, 246, 224);
    public static readonly Color WarnFg = Color.FromArgb(122, 74, 0);
    public static readonly Color Select = Color.FromArgb(213, 243, 238);
    public static readonly Color Danger = Color.FromArgb(153, 45, 45);
    public static readonly Color GridHeader = Color.FromArgb(231, 238, 242);
    public static readonly Color AltRow = Color.FromArgb(248, 250, 252);

    public static readonly Font Title = Create("Segoe UI", 18f, FontStyle.Bold);
    public static readonly Font Subtitle = Create("Segoe UI", 9f, FontStyle.Regular);
    public static readonly Font Body = Create("Segoe UI", 9.5f, FontStyle.Regular);
    public static readonly Font BodyBold = Create("Segoe UI", 9.5f, FontStyle.Bold);
    public static readonly Font Small = Create("Segoe UI", 8.5f, FontStyle.Regular);

    private static Font Create(string family, float size, FontStyle style)
    {
        try
        {
            return new Font(family, size, style, GraphicsUnit.Point);
        }
        catch (ArgumentException)
        {
            return new Font(FontFamily.GenericSansSerif, size, style, GraphicsUnit.Point);
        }
    }
}

internal sealed class ThemedProgress : Control
{
    private int _maximum = 1;
    private int _value;

    public ThemedProgress()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        Height = 8;
    }

    public int Maximum
    {
        get => _maximum;
        set
        {
            _maximum = Math.Max(1, value);
            _value = Math.Min(_value, _maximum);
            Invalidate();
        }
    }

    public int Value
    {
        get => _value;
        set
        {
            _value = Math.Clamp(value, 0, _maximum);
            Invalidate();
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        using var back = new SolidBrush(Theme.Line);
        using var fore = new SolidBrush(Theme.Accent);
        e.Graphics.FillRectangle(back, ClientRectangle);
        var width = (int)Math.Round(ClientSize.Width * (_value / (double)_maximum));
        if (width > 0)
            e.Graphics.FillRectangle(fore, 0, 0, Math.Min(width, ClientSize.Width), ClientSize.Height);
    }
}
