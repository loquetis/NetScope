using System.Globalization;
using System.Reflection;
using NetScope.Core;

namespace NetScope;

internal sealed partial class MainForm : Form
{
    private readonly UserSettings _settings = SettingsStore.Load();
    private readonly TextBox _target = new();
    private readonly ComboBox _portMode = new();
    private readonly TextBox _customPorts = new();
    private readonly NumericUpDown _concurrency = new();
    private readonly NumericUpDown _timeout = new();
    private readonly Button _scan = new();
    private readonly Button _cancel = new();
    private readonly Button _mySubnet = new();
    private readonly ThemedProgress _progress = new();
    private readonly Label _status = new();
    private readonly Label _hint = new();
    private readonly TextBox _filter = new();
    private readonly CheckBox _onlyOpen = new();
    private readonly DataGridView _grid = new();
    private readonly Label _counts = new();
    private readonly Button _exportCsv = new();
    private readonly Button _exportJson = new();
    private readonly Button _copyIps = new();
    private readonly Label _detailEmpty = new();
    private readonly Label _detailTitle = new();
    private readonly Label _detailMeta = new();
    private readonly ListView _ports = new();
    private readonly FlowLayoutPanel _actions = new();
    private readonly Label _shareHeading = new();
    private readonly Label _shareStatus = new();
    private readonly FlowLayoutPanel _shareButtons = new();
    private readonly Button _retryShares = new();
    private readonly Button _openShare = new();
    private readonly Button _copyShare = new();
    private readonly CheckBox _hideAdmin = new();
    private readonly ListView _shares = new();
    private readonly Panel _options = new();
    private readonly Panel _bottom = new();
    private readonly Panel _header = new();
    private readonly System.Windows.Forms.Timer _timer = new();

    private readonly List<HostResult> _hosts = new();
    private readonly Dictionary<string, int> _index = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SmbEnumerationResult> _shareCache = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private List<HostResult> _view = new();
    private CancellationTokenSource? _cts;
    private int _generation;
    private bool _dirty;
    private bool _refreshing;
    private bool _shareBusy;
    private string _sortColumn = "ip";
    private bool _sortAscending = true;
    private string? _shownIp;
    private string? _detailsKey;
    private SmbEnumerationResult? _shownShares;

    public MainForm(bool loadDemo = false)
    {
        Text = $"{AppInfo.Name} {AppInfo.Version}";
        Font = Theme.Body;
        BackColor = Theme.Bg;
        ForeColor = Theme.Text;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1080, 700);
        ClientSize = new Size(1280, 800);
        DoubleBuffered = true;
        KeyPreview = true;

        BuildChrome();
        BuildOptions();
        BuildDetails();
        BuildBottom();
        // WinForms docks the last Top control at the top of the form.
        Controls.Add(_body);
        Controls.Add(_bottom);
        Controls.Add(_progressHost);
        Controls.Add(_options);
        Controls.Add(_warn);
        Controls.Add(_header);
        WireEvents();
        ApplySettings();
        var detected = LocalSubnet.DetectCidr();
        _target.Text = detected ?? "";
        _status.Text = detected == null
            ? "No active IPv4 subnet was detected. Enter a target to scan."
            : $"Ready. This PC is on {detected}. TCP connect scan, no administrator rights required.";
        _timer.Interval = 120;
        _timer.Tick += (_, _) =>
        {
            if (!_dirty) return;
            _dirty = false;
            RefreshView();
        };
        _timer.Start();
        Shown += (_, _) => Task.Run(static () => OuiDatabase.Warmup());
        if (loadDemo)
        {
            ClientSize = new Size(1500, 960);
            Shown += (_, _) => ShowDemoSample();
        }
    }

    private void ShowDemoSample()
    {
        var sample = DemoCatalog.Create();
        lock (_gate)
        {
            _hosts.Clear();
            _index.Clear();
            foreach (var host in sample.Hosts)
            {
                _index[host.Address.ToString()] = _hosts.Count;
                _hosts.Add(host);
            }

            _shareCache.Clear();
            foreach (var pair in sample.Shares)
                _shareCache[pair.Key] = pair.Value;
        }

        _target.Text = "192.168.1.0/24";
        _status.Text = "Demo data only. These 8 hosts are fictional and were not scanned.";
        RefreshView();
        if (_grid.RowCount > 0 && _grid.ColumnCount > 0)
            _grid.CurrentCell = _grid.Rows[0].Cells[0];
        if (_shares.Items.Count > 0)
        {
            _shares.Items[0].Selected = true;
            _shares.Items[0].Focused = true;
        }
    }

    private void BuildChrome()
    {
        _header.Dock = DockStyle.Top;
        _header.Height = 64;
        _header.BackColor = Theme.Navy;
        var title = new Label
        {
            Text = "NetScope",
            Font = Theme.Title,
            ForeColor = Color.White,
            BackColor = Theme.Navy,
            AutoSize = true,
            Location = new Point(16, 8)
        };
        var subtitle = new Label
        {
            Text = "Hosts, ports, and shares on networks you are allowed to scan",
            Font = Theme.Subtitle,
            ForeColor = Color.FromArgb(198, 214, 230),
            BackColor = Theme.Navy,
            AutoSize = true,
            Location = new Point(18, 38)
        };
        var version = new Label
        {
            Text = AppInfo.Version,
            Font = Theme.Subtitle,
            ForeColor = Color.FromArgb(198, 214, 230),
            BackColor = Theme.Navy,
            AutoSize = true,
            Anchor = AnchorStyles.Top | AnchorStyles.Right
        };
        _header.Controls.Add(title);
        _header.Controls.Add(subtitle);
        _header.Controls.Add(version);
        _header.Resize += (_, _) => version.Location = new Point(_header.Width - version.Width - 16, 22);

        _warn = new Panel { Dock = DockStyle.Top, Height = 34, BackColor = Theme.WarnBg };
        var warnText = new Label
        {
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(16, 0, 12, 0),
            ForeColor = Theme.WarnFg,
            BackColor = Theme.WarnBg,
            Text = "Scan only networks you own or are authorized to test. Unauthorized scanning may be illegal."
        };
        _warn.Controls.Add(warnText);

        _progressHost = new Panel { Dock = DockStyle.Top, Height = 48, BackColor = Theme.Bg, Padding = new Padding(16, 6, 16, 0) };
        _progress.Dock = DockStyle.Top;
        _progress.Height = 8;
        _status.Dock = DockStyle.Fill;
        _status.ForeColor = Theme.Muted;
        _status.TextAlign = ContentAlignment.MiddleLeft;
        _hint.Dock = DockStyle.Right;
        _hint.Width = 460;
        _hint.TextAlign = ContentAlignment.MiddleRight;
        _hint.ForeColor = Theme.Muted;
        var statusRow = new Panel { Dock = DockStyle.Top, Height = 22 };
        statusRow.Controls.Add(_hint);
        statusRow.Controls.Add(_status);
        _progressHost.Controls.Add(statusRow);
        _progressHost.Controls.Add(_progress);

        _body = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg, Padding = new Padding(12, 0, 12, 8) };
        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            SplitterWidth = 8,
            BackColor = Theme.Bg
        };
        _body.Controls.Add(split);
        ((Panel)split.Panel1).BackColor = Theme.Bg;
        ((Panel)split.Panel2).BackColor = Theme.Card;
        split.Panel1.Padding = new Padding(0, 0, 4, 0);
        BuildFilterAndGrid(split.Panel1);
        _detailHost = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Card };
        split.Panel2.Controls.Add(new Panel { Dock = DockStyle.Left, Width = 4, BackColor = Theme.Accent });
        split.Panel2.Controls.Add(_detailHost);

        Load += (_, _) =>
        {
            try
            {
                var distance = Math.Max(480, split.Width - 400);
                if (distance > split.Panel1MinSize && distance < split.Width - split.Panel2MinSize)
                    split.SplitterDistance = distance;
            }
            catch (InvalidOperationException)
            {
                // The splitter picks a default when the window is not ready.
            }
        };
    }

    private Panel _detailHost = null!;
    private Panel _warn = null!;
    private Panel _progressHost = null!;
    private Panel _body = null!;

    private void BuildOptions()
    {
        _options.Dock = DockStyle.Top;
        _options.Height = 96;
        _options.BackColor = Theme.Card;
        _target.BorderStyle = BorderStyle.FixedSingle;
        _customPorts.BorderStyle = BorderStyle.FixedSingle;
        _portMode.DropDownStyle = ComboBoxStyle.DropDownList;
        _portMode.Items.AddRange(new object[] { "Common (top 100)", "All ports (1-65535)", "Custom" });
        _concurrency.Minimum = ScanLimits.MinConcurrency;
        _concurrency.Maximum = ScanLimits.MaxConcurrency;
        _timeout.Minimum = ScanLimits.MinTimeoutMs;
        _timeout.Maximum = ScanLimits.MaxTimeoutMs;
        _timeout.Increment = 50;
        StyleButton(_scan, "Scan", Theme.Accent, Color.White);
        StyleButton(_cancel, "Cancel", Theme.Line, Theme.Text);
        StyleButton(_mySubnet, "My subnet", Theme.Navy, Color.White);
        _scan.Size = new Size(108, 32);
        _cancel.Size = new Size(96, 32);
        _mySubnet.Size = new Size(104, 30);
        _cancel.Enabled = false;
        _options.Controls.AddRange(new Control[] { _target, _customPorts, _portMode, _concurrency, _timeout, _scan, _cancel, _mySubnet });
        _options.Resize += (_, _) => LayoutOptions();
    }

    private void LayoutOptions()
    {
        const int pad = 16;
        var y1 = 12;
        _mySubnet.Location = new Point(_options.ClientSize.Width - pad - _mySubnet.Width, y1);
        _target.SetBounds(72, y1 + 3, Math.Max(80, _mySubnet.Left - 80), 24);
        var y2 = 52;
        var right = _options.ClientSize.Width - pad;
        _cancel.Location = new Point(right - _cancel.Width, y2);
        _scan.Location = new Point(_cancel.Left - 8 - _scan.Width, y2);
        _timeout.SetBounds(_scan.Left - 16 - 78, y2 + 3, 78, 24);
        _concurrency.SetBounds(_timeout.Left - 168, y2 + 3, 72, 24);
        _portMode.SetBounds(60, y2 + 3, 168, 24);
        _customPorts.SetBounds(_portMode.Right + 8, y2 + 3, Math.Max(80, _concurrency.Left - 96 - (_portMode.Right + 8)), 24);
        PositionCaption(16, y1 + 6, "Target");
        PositionCaption(16, y2 + 6, "Ports");
        PositionCaption(_concurrency.Left - 92, y2 + 6, "Concurrency");
        PositionCaption(_timeout.Left - 64, y2 + 6, "Timeout");
    }

    private readonly List<Label> _optionCaptions = new();

    private void PositionCaption(int x, int y, string text)
    {
        var label = _optionCaptions.FirstOrDefault(item => item.Text == text);
        if (label == null)
        {
            label = new Label { Text = text, AutoSize = true, ForeColor = Theme.Muted, BackColor = Theme.Card };
            _optionCaptions.Add(label);
            _options.Controls.Add(label);
        }

        label.Location = new Point(x, y);
    }

    private void BuildFilterAndGrid(Control parent)
    {
        var filterRow = new Panel { Dock = DockStyle.Top, Height = 36, BackColor = Theme.Bg };
        var filterLabel = new Label { Text = "Filter", AutoSize = true, Location = new Point(0, 8), ForeColor = Theme.Muted };
        _filter.SetBounds(42, 4, 280, 24);
        _filter.BorderStyle = BorderStyle.FixedSingle;
        _filter.PlaceholderText = "IP, hostname, MAC, vendor, or port";
        _onlyOpen.Text = "Only hosts with open ports";
        _onlyOpen.AutoSize = true;
        _onlyOpen.Location = new Point(336, 6);
        filterRow.Controls.AddRange(new Control[] { filterLabel, _filter, _onlyOpen });

        ConfigureGrid();
        _grid.Dock = DockStyle.Fill;
        // Fill is added first so the filter bar docks above the grid instead of covering its headers.
        parent.Controls.Add(_grid);
        parent.Controls.Add(filterRow);
    }

    private void ConfigureGrid()
    {
        _grid.VirtualMode = true;
        _grid.ReadOnly = true;
        _grid.AllowUserToAddRows = false;
        _grid.AllowUserToDeleteRows = false;
        _grid.AllowUserToResizeRows = false;
        _grid.MultiSelect = true;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.RowHeadersVisible = false;
        _grid.ColumnHeadersVisible = true;
        _grid.BorderStyle = BorderStyle.None;
        _grid.BackgroundColor = Color.White;
        _grid.GridColor = Theme.Line;
        _grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        _grid.EnableHeadersVisualStyles = false;
        _grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.Single;
        _grid.ColumnHeadersHeight = 36;
        _grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
        _grid.RowTemplate.Height = 28;
        _grid.AutoGenerateColumns = false;
        _grid.ShowCellToolTips = true;
        _grid.DefaultCellStyle.BackColor = Color.White;
        _grid.DefaultCellStyle.ForeColor = Theme.Text;
        _grid.DefaultCellStyle.SelectionBackColor = Theme.Select;
        _grid.DefaultCellStyle.SelectionForeColor = Theme.Text;
        _grid.DefaultCellStyle.Padding = new Padding(4, 0, 4, 0);
        _grid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Navy;
        _grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
        _grid.ColumnHeadersDefaultCellStyle.Font = Theme.BodyBold;
        _grid.ColumnHeadersDefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleLeft;
        _grid.ColumnHeadersDefaultCellStyle.Padding = new Padding(8, 0, 8, 0);
        _grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = Theme.Navy;
        _grid.ColumnHeadersDefaultCellStyle.SelectionForeColor = Color.White;
        _grid.AlternatingRowsDefaultCellStyle.BackColor = Theme.AltRow;
        _grid.Columns.AddRange(
            Column("ip", ResultColumns.IpAddress, 140),
            Column("hostname", ResultColumns.Hostname, 180),
            Column("mac", ResultColumns.MacAddress, 150),
            Column("vendor", ResultColumns.Vendor, 160),
            Column("latency", ResultColumns.Latency, 120),
            Column("ports", ResultColumns.OpenPorts, 240, fill: true));
        ApplySortGlyphs();
        _grid.CellPainting += PaintColumnHeader;
        typeof(DataGridView).GetProperty("DoubleBuffered", BindingFlags.Instance | BindingFlags.NonPublic)?.SetValue(_grid, true);
    }

    private void PaintColumnHeader(object? sender, DataGridViewCellPaintingEventArgs e)
    {
        if (e.RowIndex != -1 || e.ColumnIndex < 0 || e.Graphics == null) return;
        var graphics = e.Graphics;
        var column = _grid.Columns[e.ColumnIndex];
        var bounds = e.CellBounds;
        using (var fill = new SolidBrush(Theme.Navy))
            graphics.FillRectangle(fill, bounds);
        var text = column.HeaderText ?? "";
        if (column.Name == _sortColumn)
            text += _sortAscending ? "  ▲" : "  ▼";
        var textBounds = new Rectangle(bounds.X + 8, bounds.Y, Math.Max(0, bounds.Width - 12), bounds.Height);
        TextRenderer.DrawText(
            graphics,
            text,
            Theme.BodyBold,
            textBounds,
            Color.White,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
        using var line = new Pen(Color.FromArgb(40, 70, 104));
        graphics.DrawLine(line, bounds.Left, bounds.Bottom - 1, bounds.Right - 1, bounds.Bottom - 1);
        graphics.DrawLine(line, bounds.Right - 1, bounds.Top, bounds.Right - 1, bounds.Bottom - 1);
        e.Handled = true;
    }

    private void ApplySortGlyphs()
    {
        foreach (DataGridViewColumn column in _grid.Columns)
        {
            column.HeaderCell.SortGlyphDirection = column.Name == _sortColumn
                ? (_sortAscending ? SortOrder.Ascending : SortOrder.Descending)
                : SortOrder.None;
        }
    }

    private static DataGridViewTextBoxColumn Column(string name, string header, int width, bool fill = false)
    {
        return new DataGridViewTextBoxColumn
        {
            Name = name,
            HeaderText = header,
            Width = width,
            MinimumWidth = 70,
            AutoSizeMode = fill ? DataGridViewAutoSizeColumnMode.Fill : DataGridViewAutoSizeColumnMode.None,
            SortMode = DataGridViewColumnSortMode.Programmatic
        };
    }

    private void BuildDetails()
    {
        _detailEmpty.Text = "Select a host to see names, latency, open ports, connect actions, and SMB shares.";
        _detailEmpty.Dock = DockStyle.Top;
        _detailEmpty.Height = 72;
        _detailEmpty.Padding = new Padding(14, 16, 14, 0);
        _detailEmpty.ForeColor = Theme.Muted;

        _detailTitle.Dock = DockStyle.Top;
        _detailTitle.Height = 32;
        _detailTitle.Padding = new Padding(14, 12, 14, 0);
        _detailTitle.Font = Theme.BodyBold;
        _detailMeta.Dock = DockStyle.Top;
        _detailMeta.Height = 92;
        _detailMeta.Padding = new Padding(14, 0, 14, 0);
        _detailMeta.ForeColor = Theme.Muted;

        _ports.Dock = DockStyle.Top;
        _ports.Height = 132;
        _ports.View = View.Details;
        _ports.FullRowSelect = true;
        _ports.HeaderStyle = ColumnHeaderStyle.Nonclickable;
        _ports.BorderStyle = BorderStyle.FixedSingle;
        _ports.Columns.Add("Port", 70);
        _ports.Columns.Add("Service", 120);
        _ports.Columns.Add("Banner", 160);

        _actions.Dock = DockStyle.Top;
        _actions.Height = 104;
        _actions.Padding = new Padding(10, 8, 8, 4);
        _actions.WrapContents = true;
        _actions.BackColor = Theme.Card;

        _shareHeading.Dock = DockStyle.Top;
        _shareHeading.Height = 24;
        _shareHeading.Padding = new Padding(14, 4, 14, 0);
        _shareHeading.Font = Theme.BodyBold;
        _shareHeading.Text = "SMB shares";
        _shareStatus.Dock = DockStyle.Top;
        _shareStatus.Height = 48;
        _shareStatus.Padding = new Padding(14, 0, 14, 0);
        _shareStatus.ForeColor = Theme.Muted;
        _shareButtons.Dock = DockStyle.Top;
        _shareButtons.Height = 40;
        _shareButtons.Padding = new Padding(10, 4, 8, 0);
        _shareButtons.WrapContents = false;
        StyleButton(_retryShares, "Retry with different credentials…", Theme.Navy, Color.White);
        StyleButton(_openShare, "Open in Explorer", Theme.Accent, Color.White);
        StyleButton(_copyShare, "Copy path", Theme.Line, Theme.Text);
        _retryShares.AutoSize = true;
        _retryShares.Height = 28;
        _openShare.AutoSize = true;
        _copyShare.AutoSize = true;
        _hideAdmin.Text = "Hide admin shares";
        _hideAdmin.AutoSize = true;
        _hideAdmin.Margin = new Padding(8, 6, 0, 0);
        _shareButtons.Controls.AddRange(new Control[] { _openShare, _copyShare, _retryShares, _hideAdmin });

        _shares.Dock = DockStyle.Fill;
        _shares.View = View.Details;
        _shares.FullRowSelect = true;
        _shares.HeaderStyle = ColumnHeaderStyle.Nonclickable;
        _shares.BorderStyle = BorderStyle.FixedSingle;
        _shares.Columns.Add("Share Name", 120);
        _shares.Columns.Add("Type", 80);
        _shares.Columns.Add("Admin", 64);
        _shares.Columns.Add("Remark", 120);

        _detailHost.Controls.Add(_shares);
        _detailHost.Controls.Add(_shareButtons);
        _detailHost.Controls.Add(_shareStatus);
        _detailHost.Controls.Add(_shareHeading);
        _detailHost.Controls.Add(_actions);
        _detailHost.Controls.Add(_ports);
        _detailHost.Controls.Add(_detailMeta);
        _detailHost.Controls.Add(_detailTitle);
        _detailHost.Controls.Add(_detailEmpty);
        _detailHost.Resize += (_, _) =>
        {
            if (_ports.Columns.Count == 3)
                _ports.Columns[2].Width = Math.Max(80, _ports.ClientSize.Width - 190);
            if (_shares.Columns.Count == 4)
                _shares.Columns[3].Width = Math.Max(80, _shares.ClientSize.Width - 264);
        };
        ShowEmptyDetails();
    }

    private void BuildBottom()
    {
        _bottom.Dock = DockStyle.Bottom;
        _bottom.Height = 48;
        _bottom.BackColor = Theme.Card;
        _counts.AutoSize = false;
        _counts.ForeColor = Theme.Muted;
        _counts.Text = "No scan yet";
        StyleButton(_exportCsv, "Export CSV", Theme.Navy, Color.White);
        StyleButton(_exportJson, "Export JSON", Theme.Navy, Color.White);
        StyleButton(_copyIps, "Copy IPs", Theme.Line, Theme.Text);
        _exportCsv.Size = new Size(110, 30);
        _exportJson.Size = new Size(116, 30);
        _copyIps.Size = new Size(96, 30);
        _bottom.Controls.AddRange(new Control[] { _counts, _exportCsv, _exportJson, _copyIps });
        _bottom.Resize += (_, _) =>
        {
            var x = _bottom.ClientSize.Width - 12;
            foreach (var button in new[] { _copyIps, _exportJson, _exportCsv })
            {
                button.Location = new Point(x - button.Width, 9);
                x = button.Left - 8;
            }

            _counts.SetBounds(16, 14, Math.Max(80, x - 24), 22);
        };
    }

    private void WireEvents()
    {
        _scan.Click += async (_, _) => await StartScanAsync();
        _cancel.Click += (_, _) =>
        {
            _cts?.Cancel();
            _status.Text = "Cancelling…";
        };
        _mySubnet.Click += (_, _) =>
        {
            var cidr = LocalSubnet.DetectCidr();
            if (cidr == null)
            {
                _status.Text = "No active IPv4 subnet was detected.";
                return;
            }

            _target.Text = cidr;
            _status.Text = $"Target set to this PC's subnet {cidr}.";
        };
        _target.TextChanged += (_, _) => UpdateTargetHint();
        _target.KeyDown += (_, e) =>
        {
            if (e.KeyCode != Keys.Enter) return;
            e.SuppressKeyPress = true;
            if (_scan.Enabled) _scan.PerformClick();
        };
        _customPorts.TextChanged += (_, _) => UpdateTargetHint();
        _portMode.SelectedIndexChanged += (_, _) =>
        {
            _customPorts.Enabled = _portMode.SelectedIndex == (int)PortSelectionMode.Custom;
            UpdateTargetHint();
        };
        _filter.TextChanged += (_, _) => RefreshView();
        _onlyOpen.CheckedChanged += (_, _) => RefreshView();
        _grid.CellValueNeeded += OnCellValueNeeded;
        _grid.ColumnHeaderMouseClick += (_, e) =>
        {
            if (e.ColumnIndex < 0) return;
            var name = _grid.Columns[e.ColumnIndex].Name;
            if (string.IsNullOrEmpty(name)) return;
            if (_sortColumn == name) _sortAscending = !_sortAscending;
            else
            {
                _sortColumn = name;
                _sortAscending = true;
            }
            ApplySortGlyphs();
            RefreshView();
        };
        _grid.SelectionChanged += (_, _) =>
        {
            if (!_refreshing) RenderDetails(SelectedHost());
        };
        _grid.MouseDown += OnGridMouseDown;
        _grid.KeyDown += (_, e) =>
        {
            if (e.Control && e.KeyCode == Keys.C)
            {
                CopySelectedIps();
                e.Handled = true;
            }
        };
        _exportCsv.Click += (_, _) => Export(json: false);
        _exportJson.Click += (_, _) => Export(json: true);
        _copyIps.Click += (_, _) => CopyVisibleIps();
        _hideAdmin.CheckedChanged += (_, _) =>
        {
            _settings.HideAdminShares = _hideAdmin.Checked;
            SettingsStore.Save(_settings);
            if (_shownShares != null) DisplayShares(_shownShares);
        };
        _retryShares.Click += async (_, _) =>
        {
            var host = SelectedHost();
            if (host != null) await ListSharesAsync(host, prompt: _shownShares?.Status == SmbStatus.AccessDenied);
        };
        _openShare.Click += (_, _) => OpenSelectedShare();
        _copyShare.Click += (_, _) => CopySelectedShare();
        _shares.SelectedIndexChanged += (_, _) => UpdateShareButtons();
        _shares.MouseUp += (_, e) =>
        {
            if (e.Button != MouseButtons.Right) return;
            var hit = _shares.HitTest(e.Location);
            if (hit.Item == null) return;
            hit.Item.Selected = true;
            var menu = new ContextMenuStrip();
            menu.Items.Add("Open in Explorer", null, (_, _) => OpenSelectedShare());
            menu.Items.Add("Copy path", null, (_, _) => CopySelectedShare());
            menu.Closed += (_, _) => menu.Dispose();
            menu.Show(_shares, e.Location);
        };
        KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Escape && _cancel.Enabled)
                _cancel.PerformClick();
        };
    }

    private void ApplySettings()
    {
        _concurrency.Value = _settings.Concurrency;
        _timeout.Value = _settings.TimeoutMs;
        _portMode.SelectedIndex = _settings.PortMode;
        _customPorts.Text = _settings.CustomPorts;
        _hideAdmin.Checked = _settings.HideAdminShares;
        _onlyOpen.Checked = _settings.OnlyOpenPorts;
        _customPorts.Enabled = _portMode.SelectedIndex == (int)PortSelectionMode.Custom;
    }

    private static void StyleButton(Button button, string text, Color back, Color fore)
    {
        button.Text = text;
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderSize = 0;
        button.BackColor = back;
        button.ForeColor = fore;
        button.Cursor = Cursors.Hand;
        button.Margin = new Padding(4, 2, 4, 2);
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        _cts?.Cancel();
        base.OnFormClosing(e);
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _timer.Stop();
        _timer.Dispose();
        _cts?.Dispose();
        base.OnFormClosed(e);
    }
}
