using System.Diagnostics;
using System.Globalization;
using NetScope.Core;

namespace NetScope;

internal sealed partial class MainForm
{
    private async Task StartScanAsync()
    {
        if (!TryBuildRequest(out var targets, out var ports, out var options, out var error))
        {
            MessageBox.Show(this, error, "Check the target", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var checks = (long)targets.Count * ports.Count;
        if (checks > ScanLimits.LargeScanThreshold)
        {
            var answer = MessageBox.Show(
                this,
                $"This scan can attempt about {checks:N0} TCP connections across {targets.Count:N0} hosts. Large scans take longer and can trip firewalls or intrusion detection. Continue?",
                "Large scan",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes)
                return;
        }

        SaveUiSettings();
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        var generation = ++_generation;
        lock (_gate)
        {
            _hosts.Clear();
            _index.Clear();
        }

        _shareCache.Clear();
        _detailsKey = null;
        _shownShares = null;
        RefreshView();
        SetScanning(true);
        var progress = new Progress<ScanProgress>(update =>
        {
            if (generation != _generation) return;
            _progress.Maximum = Math.Max(1, update.Total);
            _progress.Value = Math.Clamp(update.Completed, 0, _progress.Maximum);
            _status.Text = update.Total == 0
                ? update.Phase
                : $"{update.Phase}: {update.Completed:N0} / {update.Total:N0}";
        });

        try
        {
            await NetworkScanner.ScanAsync(
                targets,
                ports,
                options,
                progress,
                host => DeliverHost(generation, host),
                token);
            if (generation != _generation) return;
            int count;
            lock (_gate) count = _hosts.Count;
            _status.Text = count == 0
                ? "Done. No hosts responded. ICMP may be blocked, and the TCP fallback ports may be closed."
                : $"Done. {count:N0} host(s) responded.";
        }
        catch (OperationCanceledException)
        {
            if (generation == _generation)
                _status.Text = "Scan cancelled.";
        }
        catch (Exception ex)
        {
            if (generation != _generation) return;
            _status.Text = "Scan failed.";
            MessageBox.Show(this, ex.Message, "NetScope", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            if (generation == _generation)
            {
                SetScanning(false);
                _dirty = true;
                RefreshView();
            }
        }
    }

    private void DeliverHost(int generation, HostResult host)
    {
        if (generation != _generation) return;
        lock (_gate)
        {
            var key = host.Address.ToString();
            if (!_index.ContainsKey(key))
            {
                _index[key] = _hosts.Count;
                _hosts.Add(host);
            }
        }

        if (IsDisposed || !IsHandleCreated) return;
        try
        {
            BeginInvoke(() =>
            {
                if (generation == _generation && !IsDisposed)
                    _dirty = true;
            });
        }
        catch (InvalidOperationException)
        {
            // The window closed while a result was in flight.
        }
    }

    private bool TryBuildRequest(out IReadOnlyList<System.Net.IPAddress> targets, out IReadOnlyList<int> ports, out ScanOptions options, out string error)
    {
        targets = Array.Empty<System.Net.IPAddress>();
        ports = Array.Empty<int>();
        options = new ScanOptions(ScanLimits.DefaultConcurrency, ScanLimits.DefaultTimeoutMs, true);
        error = "";
        try
        {
            targets = TargetParser.Parse(_target.Text);
            var mode = (PortSelectionMode)_portMode.SelectedIndex;
            ports = PortListParser.ForMode(mode, _customPorts.Text);
            var concurrency = (int)_concurrency.Value;
            var timeout = (int)_timeout.Value;
            ScanLimits.ValidateConcurrency(concurrency);
            ScanLimits.ValidateTimeout(timeout);
            options = new ScanOptions(concurrency, timeout, GrabBanners: true);
            return true;
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or ArgumentOutOfRangeException)
        {
            error = ex.Message;
            return false;
        }
    }

    private void SaveUiSettings()
    {
        _settings.Concurrency = (int)_concurrency.Value;
        _settings.TimeoutMs = (int)_timeout.Value;
        _settings.PortMode = _portMode.SelectedIndex;
        _settings.CustomPorts = _customPorts.Text;
        _settings.HideAdminShares = _hideAdmin.Checked;
        _settings.OnlyOpenPorts = _onlyOpen.Checked;
        SettingsStore.Save(_settings);
    }

    private void SetScanning(bool scanning)
    {
        _scan.Enabled = !scanning;
        _cancel.Enabled = scanning;
        _target.Enabled = !scanning;
        _portMode.Enabled = !scanning;
        _customPorts.Enabled = !scanning && _portMode.SelectedIndex == (int)PortSelectionMode.Custom;
        _concurrency.Enabled = !scanning;
        _timeout.Enabled = !scanning;
        _mySubnet.Enabled = !scanning;
        if (!scanning && _progress.Maximum > 0)
            _progress.Value = _progress.Maximum;
    }

    private void UpdateTargetHint()
    {
        try
        {
            var hosts = TargetParser.Parse(_target.Text);
            var mode = _portMode.SelectedIndex < 0 ? PortSelectionMode.Common : (PortSelectionMode)_portMode.SelectedIndex;
            var ports = mode == PortSelectionMode.Custom && string.IsNullOrWhiteSpace(_customPorts.Text)
                ? Array.Empty<int>()
                : PortListParser.ForMode(mode, _customPorts.Text);
            _hint.ForeColor = Theme.Muted;
            _hint.Text = $"{hosts.Count:N0} host(s) · {ports.Count:N0} port(s)";
        }
        catch (FormatException ex)
        {
            _hint.ForeColor = Theme.Danger;
            _hint.Text = ex.Message;
        }
    }

    private void RefreshView()
    {
        if (_refreshing) return;
        _refreshing = true;
        try
        {
            var selected = SelectedHost()?.Address.ToString();
            List<HostResult> snapshot;
            lock (_gate) snapshot = _hosts.ToList();
            IEnumerable<HostResult> query = snapshot;
            var filter = _filter.Text.Trim();
            if (filter.Length > 0)
                query = query.Where(host => Matches(host, filter));
            if (_onlyOpen.Checked)
                query = query.Where(host => host.CopyPorts().Count > 0);
            var list = query.ToList();
            list.Sort(CompareHosts);
            _view = list;
            _grid.RowCount = _view.Count;
            _grid.Invalidate();
            if (selected != null)
            {
                var index = _view.FindIndex(host => host.Address.ToString() == selected);
                if (index >= 0 && _grid.ColumnCount > 0 && index < _grid.RowCount)
                    _grid.CurrentCell = _grid.Rows[index].Cells[0];
            }

            var openHosts = snapshot.Count(host => host.CopyPorts().Count > 0);
            _counts.Text = snapshot.Count == 0
                ? "No responding hosts"
                : $"{_view.Count:N0} shown · {snapshot.Count:N0} responding · {openHosts:N0} with open ports";
            RenderDetails(SelectedHost());
        }
        finally
        {
            _refreshing = false;
        }
    }

    private static bool Matches(HostResult host, string filter)
    {
        return host.Address.ToString().Contains(filter, StringComparison.OrdinalIgnoreCase)
            || host.Hostname.Contains(filter, StringComparison.OrdinalIgnoreCase)
            || (host.DnsName?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
            || (host.NetBiosName?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
            || (host.MdnsName?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
            || (host.MacAddress?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
            || (host.Vendor?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
            || host.PortsSummary.Contains(filter, StringComparison.OrdinalIgnoreCase);
    }

    private int CompareHosts(HostResult left, HostResult right)
    {
        var sign = _sortAscending ? 1 : -1;
        var compared = _sortColumn switch
        {
            "hostname" => string.Compare(left.Hostname, right.Hostname, StringComparison.OrdinalIgnoreCase),
            "mac" => string.Compare(left.MacAddress, right.MacAddress, StringComparison.OrdinalIgnoreCase),
            "vendor" => string.Compare(left.Vendor, right.Vendor, StringComparison.OrdinalIgnoreCase),
            "latency" => CompareLatency(left.LatencyMs, right.LatencyMs),
            "ports" => left.CopyPorts().Count.CompareTo(right.CopyPorts().Count),
            _ => TargetParser.ToUInt(left.Address).CompareTo(TargetParser.ToUInt(right.Address))
        };
        if (compared == 0)
            compared = TargetParser.ToUInt(left.Address).CompareTo(TargetParser.ToUInt(right.Address));
        return compared * sign;
    }

    private static int CompareLatency(long? left, long? right)
    {
        if (left == null && right == null) return 0;
        if (left == null) return 1;
        if (right == null) return -1;
        return left.Value.CompareTo(right.Value);
    }

    private void OnCellValueNeeded(object? sender, DataGridViewCellValueEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _view.Count) return;
        var host = _view[e.RowIndex];
        e.Value = _grid.Columns[e.ColumnIndex].Name switch
        {
            "ip" => host.Address.ToString(),
            "hostname" => host.Hostname,
            "mac" => host.MacAddress ?? "",
            "vendor" => host.Vendor ?? "",
            "latency" => host.LatencyMs?.ToString(CultureInfo.InvariantCulture) ?? "",
            "ports" => host.PortsSummary,
            _ => ""
        };
    }

    private void OnGridMouseDown(object? sender, MouseEventArgs e)
    {
        if (e.Button != MouseButtons.Right) return;
        var hit = _grid.HitTest(e.X, e.Y);
        if (hit.RowIndex < 0 || hit.RowIndex >= _view.Count || hit.ColumnIndex < 0) return;
        _grid.CurrentCell = _grid.Rows[hit.RowIndex].Cells[hit.ColumnIndex];
        ShowContextMenu(_view[hit.RowIndex], _grid.PointToScreen(e.Location));
    }

    private void ShowContextMenu(HostResult host, Point screen)
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Copy IP", null, (_, _) => CopyText(host.Address.ToString()));
        menu.Items.Add("Copy hostname", null, (_, _) => CopyText(string.IsNullOrWhiteSpace(host.Hostname) ? host.Address.ToString() : host.Hostname));
        if (!string.IsNullOrWhiteSpace(host.MacAddress))
            menu.Items.Add("Copy MAC", null, (_, _) => CopyText(host.MacAddress));
        menu.Items.Add("Copy row", null, (_, _) => CopyText(FormatRow(host)));
        var ports = host.CopyPorts();
        if (ports.Any(port => port.IsRdp || port.IsSsh || port.IsSmb))
            menu.Items.Add(new ToolStripSeparator());
        foreach (var port in ports.Where(port => port.IsRdp))
        {
            var number = port.Number;
            menu.Items.Add($"Connect with Remote Desktop ({number})", null, (_, _) => ConnectRdp(host, number));
        }

        foreach (var port in ports.Where(port => port.IsSsh))
        {
            var number = port.Number;
            menu.Items.Add($"Connect with SSH ({number})", null, (_, _) => ConnectSsh(host, number));
        }

        if (ports.Any(port => port.IsSmb))
            menu.Items.Add("List shares", null, async (_, _) => await ListSharesAsync(host, prompt: false));
        menu.Closed += (_, _) => menu.Dispose();
        menu.Show(screen);
    }

    private HostResult? SelectedHost()
    {
        if (_grid.CurrentCell == null) return null;
        var row = _grid.CurrentCell.RowIndex;
        if (row < 0 || row >= _view.Count) return null;
        return _view[row];
    }

    private void RenderDetails(HostResult? host)
    {
        var key = host == null
            ? ""
            : string.Join('|', host.Address, host.Hostname, host.DnsName, host.NetBiosName, host.MdnsName, host.MacAddress, host.Vendor, host.LatencyMs, host.PortsSummary);
        if (key == _detailsKey) return;
        var sameHost = host != null && _shownIp == host.Address.ToString();
        _detailsKey = key;
        _shownIp = host?.Address.ToString();
        if (host == null)
        {
            ShowEmptyDetails();
            return;
        }

        _detailEmpty.Visible = false;
        _detailTitle.Visible = true;
        _detailMeta.Visible = true;
        _ports.Visible = true;
        _actions.Visible = true;
        _shareHeading.Visible = true;
        _shareStatus.Visible = true;
        _shareButtons.Visible = true;
        _shares.Visible = true;
        _detailTitle.Text = host.Address.ToString();
        _detailMeta.Text =
            $"Hostname  {(string.IsNullOrWhiteSpace(host.Hostname) ? "—" : host.Hostname)}\n" +
            $"DNS  {Blank(host.DnsName)}    NetBIOS  {Blank(host.NetBiosName)}    mDNS  {Blank(host.MdnsName)}\n" +
            $"MAC  {Blank(host.MacAddress)}    Vendor  {Blank(host.Vendor)}\n" +
            $"Latency  {(host.LatencyMs is long ms ? $"{ms} ms" : "—")}";
        _ports.BeginUpdate();
        _ports.Items.Clear();
        foreach (var port in host.CopyPorts())
        {
            var item = new ListViewItem(port.Number.ToString(CultureInfo.InvariantCulture));
            item.SubItems.Add(port.Service);
            item.SubItems.Add(port.Banner ?? "");
            _ports.Items.Add(item);
        }

        _ports.EndUpdate();
        RebuildActions(host);
        if (!sameHost)
        {
            if (_shownIp != null && _shareCache.TryGetValue(_shownIp, out var cached))
                DisplayShares(cached);
            else
                ShowSharePrompt(host);
        }
    }

    private void ShowEmptyDetails()
    {
        _detailEmpty.Visible = true;
        _detailTitle.Visible = false;
        _detailMeta.Visible = false;
        _ports.Visible = false;
        _actions.Visible = false;
        _shareHeading.Visible = false;
        _shareStatus.Visible = false;
        _shareButtons.Visible = false;
        _shares.Visible = false;
        _shareStatus.Text = "";
        _shownShares = null;
        _shares.Items.Clear();
        _retryShares.Visible = false;
        UpdateShareButtons();
    }

    private static string Blank(string? value) => string.IsNullOrWhiteSpace(value) ? "—" : value;

    private void RebuildActions(HostResult host)
    {
        while (_actions.Controls.Count > 0)
        {
            var control = _actions.Controls[0];
            _actions.Controls.RemoveAt(0);
            control.Dispose();
        }

        _actions.Controls.Add(ActionButton("Copy IP", () => CopyText(host.Address.ToString())));
        _actions.Controls.Add(ActionButton("Copy row", () => CopyText(FormatRow(host))));
        foreach (var port in host.CopyPorts().Where(port => port.IsRdp))
        {
            var number = port.Number;
            _actions.Controls.Add(ActionButton($"Connect RDP {number}", () => ConnectRdp(host, number), accent: true));
        }

        foreach (var port in host.CopyPorts().Where(port => port.IsSsh))
        {
            var number = port.Number;
            _actions.Controls.Add(ActionButton($"Connect SSH {number}", () => ConnectSsh(host, number), accent: true));
        }

        if (host.CopyPorts().Any(port => port.IsSmb))
            _actions.Controls.Add(ActionButton("List shares", async () => await ListSharesAsync(host, prompt: false), accent: true));
    }

    private Button ActionButton(string text, Action click, bool accent = false)
    {
        var button = new Button { AutoSize = true, Height = 28, Margin = new Padding(4) };
        StyleButton(button, text, accent ? Theme.Accent : Theme.Line, accent ? Color.White : Theme.Text);
        button.Click += (_, _) => click();
        return button;
    }

    private void ShowSharePrompt(HostResult host)
    {
        _shownShares = null;
        _shares.Items.Clear();
        var smb = host.CopyPorts().Where(port => port.IsSmb).Select(port => port.Number).Distinct().OrderBy(port => port).ToArray();
        _shareStatus.Text = smb.Length == 0
            ? "SMB ports 139 and 445 are not open on this host."
            : $"Port {string.Join(" and ", smb)} is open. List shares uses your current Windows account and times out after 8 seconds. Passwords are never stored.";
        _retryShares.Visible = false;
        UpdateShareButtons();
    }

    private async Task ListSharesAsync(HostResult host, bool prompt)
    {
        if (_shareBusy) return;
        string? username = null;
        string? password = null;
        if (prompt)
        {
            if (!OperatingSystem.IsWindows())
            {
                MessageBox.Show(this, "The Windows credential dialog is available when NetScope is running on Windows.", "SMB", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            try
            {
                if (!WindowsCredentialPrompt.TryPrompt(this, host.Address.ToString(), out username, out password))
                    return;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "SMB", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
        }

        _shareBusy = true;
        _shareStatus.Text = "Contacting SMB…";
        try
        {
            var result = await WindowsSmb.EnumerateAsync(host.Address.ToString(), username, password, 8000, CancellationToken.None);
            _shareCache[host.Address.ToString()] = result;
            if (!IsDisposed && _shownIp == host.Address.ToString())
                DisplayShares(result);
        }
        catch (Exception ex)
        {
            if (!IsDisposed)
                _shareStatus.Text = ex.Message;
        }
        finally
        {
            password = null;
            _shareBusy = false;
        }
    }

    private void DisplayShares(SmbEnumerationResult result)
    {
        _shownShares = result;
        var visible = SmbShareClassifier.Filter(result.Shares, _hideAdmin.Checked);
        _shares.BeginUpdate();
        _shares.Items.Clear();
        foreach (var share in visible)
        {
            var item = new ListViewItem(share.Name) { Tag = share };
            item.SubItems.Add(share.KindLabel);
            item.SubItems.Add(share.IsAdmin ? "Admin" : "");
            item.SubItems.Add(share.Remark);
            if (share.IsAdmin)
                item.ForeColor = Theme.Danger;
            _shares.Items.Add(item);
        }

        _shares.EndUpdate();
        var hidden = result.Shares.Count - visible.Count;
        var suffix = hidden > 0 ? $" {hidden} admin share(s) hidden." : "";
        _shareStatus.Text = result.Message + suffix;
        _retryShares.Visible = result.Status != SmbStatus.Ok;
        _retryShares.Text = result.Status == SmbStatus.AccessDenied
            ? "Retry with different credentials…"
            : "Try again";
        UpdateShareButtons();
    }

    private SmbShare? SelectedShare()
        => _shares.SelectedItems.Count == 0 ? null : _shares.SelectedItems[0].Tag as SmbShare;

    private void UpdateShareButtons()
    {
        var share = SelectedShare();
        var disk = share is { Kind: ShareKind.Disk };
        _openShare.Enabled = disk;
        _copyShare.Enabled = disk;
    }

    private void OpenSelectedShare()
    {
        var host = SelectedHost();
        var share = SelectedShare();
        if (host == null || share == null) return;
        if (share.Kind != ShareKind.Disk)
        {
            MessageBox.Show(this, "Only disk shares can be opened in Explorer.", "SMB", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        try
        {
            var unc = SmbShare.FormatUnc(host.Address.ToString(), share.Name);
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = ShellActions.BuildExplorerArguments(unc),
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Explorer", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void CopySelectedShare()
    {
        var host = SelectedHost();
        var share = SelectedShare();
        if (host == null || share == null || share.Kind != ShareKind.Disk) return;
        try
        {
            CopyText(SmbShare.FormatUnc(host.Address.ToString(), share.Name));
            _status.Text = "Copied the share path.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Copy path", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void ConnectRdp(HostResult host, int port)
    {
        try
        {
            var target = ConnectCommands.SelectHost(host.DnsName, host.NetBiosName, host.MdnsName, host.Address.ToString());
            if (!ConnectCommands.MstscExists())
            {
                MessageBox.Show(this, "Remote Desktop (mstsc.exe) was not found on this PC.", "Remote Desktop", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var launch = ConnectCommands.BuildRdp(target, port);
            Process.Start(new ProcessStartInfo
            {
                FileName = launch.FileName,
                Arguments = launch.Arguments,
                UseShellExecute = true
            });
            _status.Text = $"Opened Remote Desktop to {target}:{port}.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Remote Desktop", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void ConnectSsh(HostResult host, int port)
    {
        var target = ConnectCommands.SelectHost(host.DnsName, host.NetBiosName, host.MdnsName, host.Address.ToString());
        using var dialog = new SshUserDialog(_settings.LastSshUsername);
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            var availability = ConnectCommands.FromProbe(ConnectCommands.ProbeInstalledClients());
            var launch = ConnectCommands.BuildSsh(dialog.Username, target, port, availability);
            if (launch.Kind == SshClientKind.Missing)
            {
                MessageBox.Show(this, launch.Message, "SSH client not found", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = launch.FileName,
                Arguments = launch.Arguments,
                UseShellExecute = true
            });
            _settings.LastSshUsername = dialog.Username;
            SettingsStore.Save(_settings);
            _status.Text = $"Opened SSH to {target}:{port}. The password stays in that window.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "SSH", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void Export(bool json)
    {
        if (_view.Count == 0)
        {
            MessageBox.Show(this, "There are no hosts to export.", "Export", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dialog = new SaveFileDialog
        {
            Filter = json ? "JSON (*.json)|*.json" : "CSV (*.csv)|*.csv",
            FileName = json ? "netscope.json" : "netscope.csv",
            Title = json ? "Export JSON" : "Export CSV"
        };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            File.WriteAllText(dialog.FileName, json ? ResultExporter.ToJson(_view) : ResultExporter.ToCsv(_view));
            _status.Text = $"Exported {_view.Count:N0} host(s).";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Export", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void CopyVisibleIps()
    {
        if (_view.Count == 0) return;
        CopyText(string.Join(Environment.NewLine, _view.Select(host => host.Address.ToString())));
        _status.Text = $"Copied {_view.Count:N0} IP address(es).";
    }

    private void CopySelectedIps()
    {
        var ips = _grid.SelectedRows.Cast<DataGridViewRow>()
            .Select(row => row.Index)
            .Where(index => index >= 0 && index < _view.Count)
            .Select(index => _view[index].Address.ToString())
            .Distinct()
            .ToArray();
        if (ips.Length == 0)
        {
            var host = SelectedHost();
            if (host == null) return;
            CopyText(host.Address.ToString());
            return;
        }

        CopyText(string.Join(Environment.NewLine, ips));
    }

    private static string FormatRow(HostResult host)
        => string.Join('\t', host.Address, host.Hostname, host.MacAddress ?? "", host.Vendor ?? "", host.LatencyMs?.ToString(CultureInfo.InvariantCulture) ?? "", host.PortsSummary);

    private void CopyText(string text)
    {
        try
        {
            Clipboard.SetText(text);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Could not copy to the clipboard. " + ex.Message, "Copy", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }
}
