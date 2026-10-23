using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetScope.Core;

public readonly record struct IcmpResult(bool Success, long RoundtripMs);

public interface IIcmpProbe
{
    Task<IcmpResult> ProbeAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken);
}

public sealed class SystemIcmpProbe : IIcmpProbe
{
    public async Task<IcmpResult> ProbeAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken)
    {
        using var ping = new Ping();
        using var registration = cancellationToken.Register(() =>
        {
            try { ping.Dispose(); } catch { /* already finished */ }
        });
        try
        {
            var reply = await ping.SendPingAsync(address, timeoutMs).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (reply.Status == IPStatus.Success)
                return new IcmpResult(true, reply.RoundtripTime);
            return default;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch
        {
            return default;
        }
    }
}

public sealed class NeverIcmpProbe : IIcmpProbe
{
    public Task<IcmpResult> ProbeAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new IcmpResult(false, 0));
    }
}

public static class HostDiscovery
{
    public static readonly int[] FallbackPorts = { 445, 80, 443, 22, 139, 135, 3389, 8080 };

    public static async Task<HostResult?> DiscoverAsync(
        IPAddress address,
        int pingTimeoutMs,
        int connectTimeoutMs,
        IIcmpProbe icmp,
        CancellationToken cancellationToken,
        IReadOnlyList<int>? fallbackPorts = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var ports = fallbackPorts ?? FallbackPorts;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var pingTask = SafePing(icmp, address, pingTimeoutMs, linked.Token);
        var tcpTask = FirstOpenAsync(address, ports, connectTimeoutMs, linked.Token);
        try
        {
            var ping = await pingTask.ConfigureAwait(false);
            if (ping.Success)
            {
                linked.Cancel();
                PortScanner.Observe(tcpTask);
                return new HostResult { Address = address, LatencyMs = ping.RoundtripMs };
            }

            if (await tcpTask.ConfigureAwait(false))
                return new HostResult { Address = address, LatencyMs = Math.Max(0, sw.ElapsedMilliseconds) };

            return null;
        }
        catch (OperationCanceledException)
        {
            linked.Cancel();
            PortScanner.Observe(tcpTask);
            throw;
        }
    }

    public static async Task<bool> TryConnectAsync(IPAddress address, int port, int timeoutMs, CancellationToken cancellationToken)
    {
        var client = new TcpClient { NoDelay = true };
        try
        {
            var connect = client.ConnectAsync(address, port);
            var finished = await Task.WhenAny(connect, Task.Delay(timeoutMs, cancellationToken)).ConfigureAwait(false);
            if (finished != connect)
            {
                PortScanner.Observe(connect);
                if (cancellationToken.IsCancellationRequested)
                    throw new OperationCanceledException(cancellationToken);
                return false;
            }

            await connect.ConfigureAwait(false);
            return client.Connected;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return false;
        }
        finally
        {
            client.Dispose();
        }
    }

    private static async Task<IcmpResult> SafePing(IIcmpProbe icmp, IPAddress address, int timeoutMs, CancellationToken cancellationToken)
    {
        try
        {
            return await icmp.ProbeAsync(address, timeoutMs, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return default;
        }
    }

    private static async Task<bool> FirstOpenAsync(
        IPAddress address,
        IReadOnlyList<int> ports,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        if (ports.Count == 0)
            return false;

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var tasks = ports.Select(port => TryConnectAsync(address, port, timeoutMs, linked.Token)).ToArray();
        try
        {
            var pending = tasks.ToList();
            while (pending.Count > 0)
            {
                var done = await Task.WhenAny(pending).ConfigureAwait(false);
                pending.Remove(done);
                if (done.IsCanceled)
                    continue;
                if (done.IsFaulted)
                {
                    PortScanner.Observe(done);
                    continue;
                }

                if (done.Result)
                {
                    linked.Cancel();
                    foreach (var leftover in pending)
                        PortScanner.Observe(leftover);
                    return true;
                }
            }
        }
        finally
        {
            linked.Cancel();
        }

        cancellationToken.ThrowIfCancellationRequested();
        return false;
    }
}
