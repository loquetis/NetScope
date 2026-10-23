namespace NetScope;

internal sealed class SshUserDialog : Form
{
    private readonly TextBox _user = new();

    public SshUserDialog(string? lastUsername)
    {
        Text = "Connect with SSH";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(440, 188);
        Font = Theme.Body;
        BackColor = Theme.Card;

        var note = new Label
        {
            Text = "A new terminal window will open. Leave the username blank to use your Windows account. NetScope never asks for or stores the SSH password.",
            Location = new Point(16, 14),
            Size = new Size(408, 52),
            ForeColor = Theme.Muted
        };
        var label = new Label
        {
            Text = "Username",
            Location = new Point(16, 74),
            AutoSize = true
        };
        _user.Location = new Point(16, 96);
        _user.Width = 408;
        _user.Text = lastUsername ?? "";
        var connect = new Button
        {
            Text = "Connect",
            DialogResult = DialogResult.OK,
            Location = new Point(228, 140),
            Size = new Size(96, 32)
        };
        var cancel = new Button
        {
            Text = "Cancel",
            DialogResult = DialogResult.Cancel,
            Location = new Point(328, 140),
            Size = new Size(96, 32)
        };
        Style(connect, Theme.Accent, Color.White);
        Style(cancel, Theme.Line, Theme.Text);
        AcceptButton = connect;
        CancelButton = cancel;
        Controls.AddRange(new Control[] { note, label, _user, connect, cancel });
    }

    public string Username => _user.Text.Trim();

    private static void Style(Button button, Color back, Color fore)
    {
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderSize = 0;
        button.BackColor = back;
        button.ForeColor = fore;
        button.Cursor = Cursors.Hand;
    }
}
