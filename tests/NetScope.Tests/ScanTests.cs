using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NetScope.Core;

namespace NetScope.Tests;

public class PortScannerTests
{
    [Fact]
    public async Task Scan_reports_a_local_listener_and_ignores_a_closed_port()
    {
        await using var listener = new LoopbackListener("SSH-2.0-NetScopeTest\r\n");
        using var closedBind = new TcpListener(IPAddress.Loopback, 0);
        closedBind.Start();
        var closed = ((IPEndPoint)closedBind.LocalEndpoint).Port;
        closedBind.Stop();

        var open = await PortScanner.ScanAsync(
            IPAddress.Loopback,
            new[] { listener.Port, closed },
            timeoutMs: 500,
            concurrency: 4,
            grabBanners: true,
            CancellationToken.None);

        var found = Assert.Single(open);
        Assert.Equal(listener.Port, found.Number);
        Assert.True(found.IsSsh);
        Assert.Equal("ssh", found.Service);
        Assert.Contains("SSH-2.0-NetScopeTest", found.Banner);
    }

    [Fact]
    public async Task Silent_listener_is_not_marked_as_an_ssh_banner()
    {
        await using var listener = new LoopbackListener(banner: null);
        var open = await PortScanner.ScanAsync(IPAddress.Loopback, new[] { listener.Port }, 500, 2, true, CancellationToken.None);
        var found = Assert.Single(open);
        Assert.False(found.SshDetected);
        Assert.False(found.IsSsh);
        Assert.NotEqual(22, found.Number);
    }

    [Fact(Timeout = 20000)]
    public async Task Cancellation_returns_before_the_connect_timeout()
    {
        using var cts = new CancellationTokenSource(200);
        var ports = Enumerable.Range(20, 8).ToArray();
        var watch = Stopwatch.StartNew();
        try
        {
            await PortScanner.ScanAsync(IPAddress.Parse("192.0.2.1"), ports, timeoutMs: 10000, concurrency: 2, grabBanners: false, cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Expected when the connects are still outstanding.
        }

        watch.Stop();
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(8), $"scan ran for {watch.Elapsed}");
    }
}

public class DiscoveryTests
{
    [Fact]
    public async Task Tcp_fallback_finds_a_host_when_icmp_never_answers()
    {
        await using var listener = new LoopbackListener(null);
        var host = await HostDiscovery.DiscoverAsync(
            IPAddress.Loopback,
            pingTimeoutMs: 200,
            connectTimeoutMs: 500,
            icmp: new NeverIcmpProbe(),
            CancellationToken.None,
            fallbackPorts: new[] { listener.Port });

        Assert.NotNull(host);
        Assert.Equal(IPAddress.Loopback, host!.Address);
        Assert.NotNull(host.LatencyMs);
    }

    [Fact]
    public async Task Scanner_records_the_open_port_on_a_live_local_host()
    {
        await using var listener = new LoopbackListener("SSH-2.0-NetScopeTest\r\n");
        using var closedBind = new TcpListener(IPAddress.Loopback, 0);
        closedBind.Start();
        var closed = ((IPEndPoint)closedBind.LocalEndpoint).Port;
        closedBind.Stop();

        HostResult? seen = null;
        await NetworkScanner.ScanAsync(
            new[] { IPAddress.Loopback },
            new[] { listener.Port, closed },
            new ScanOptions(8, 500, GrabBanners: true),
            progress: null,
            host => seen = host,
            CancellationToken.None,
            icmp: new NeverIcmpProbe(),
            discoveryPorts: new[] { listener.Port },
            resolveIdentity: false);

        Assert.NotNull(seen);
        Assert.Contains(seen!.CopyPorts(), port => port.Number == listener.Port && port.IsSsh);
        Assert.DoesNotContain(seen.CopyPorts(), port => port.Number == closed);
    }
}

internal sealed class LoopbackListener : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public LoopbackListener(string? banner)
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _loop = Task.Run(() => AcceptLoop(banner));
    }

    public int Port { get; }

    private async Task AcceptLoop(string? banner)
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_cts.Token);
            }
            catch
            {
                break;
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    if (banner != null)
                    {
                        var bytes = Encoding.ASCII.GetBytes(banner);
                        var stream = client.GetStream();
                        await stream.WriteAsync(bytes);
                        await stream.FlushAsync();
                    }

                    await Task.Delay(800);
                }
                catch
                {
                    // The scanner closes the socket after reading the banner.
                }
                finally
                {
                    client.Dispose();
                }
            });
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        try { await _loop; } catch { /* accept loop ends when the listener stops */ }
        _cts.Dispose();
    }
}
