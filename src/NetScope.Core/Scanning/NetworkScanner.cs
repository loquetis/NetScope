using System.Collections.Concurrent;
using System.Net;

namespace NetScope.Core;

public static class NetworkScanner
{
    public static async Task ScanAsync(
        IReadOnlyList<IPAddress> targets,
        IReadOnlyList<int> ports,
        ScanOptions options,
        IProgress<ScanProgress>? progress,
        Action<HostResult> onHost,
        CancellationToken cancellationToken,
        IIcmpProbe? icmp = null,
        IReadOnlyList<int>? discoveryPorts = null,
        bool resolveIdentity = true)
    {
        ArgumentNullException.ThrowIfNull(targets);
        ArgumentNullException.ThrowIfNull(ports);
        ArgumentNullException.ThrowIfNull(onHost);
        ScanLimits.ValidateConcurrency(options.Concurrency);
        ScanLimits.ValidateTimeout(options.TimeoutMs);
        if (ports.Count == 0)
            throw new ArgumentException("Choose at least one TCP port to scan.", nameof(ports));
        if (targets.Count == 0)
            return;

        icmp ??= new SystemIcmpProbe();
        var live = new ConcurrentBag<HostResult>();
        var discovered = 0;
        var liveCount = 0;
        var lastReport = 0L;

        void Report(string phase, int completed, int total)
        {
            var now = Environment.TickCount64;
            if (completed != total && now - Interlocked.Read(ref lastReport) < 100)
                return;
            Interlocked.Exchange(ref lastReport, now);
            progress?.Report(new ScanProgress(phase, completed, total));
        }

        Report("Discovering hosts (0 up)", 0, targets.Count);
        var discoverOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = options.Concurrency,
            CancellationToken = cancellationToken
        };

        await Parallel.ForEachAsync(targets, discoverOptions, async (address, token) =>
        {
            HostResult? host = null;
            try
            {
                host = await HostDiscovery.DiscoverAsync(
                    address,
                    ScanLimits.PingTimeoutMs,
                    Math.Min(options.TimeoutMs, 500),
                    icmp,
                    token,
                    discoveryPorts).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                host = null;
            }

            var done = Interlocked.Increment(ref discovered);
            if (host != null)
            {
                var up = Interlocked.Increment(ref liveCount);
                if (resolveIdentity)
                {
                    try { await IdentityResolver.EnrichAsync(host, token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { throw; }
                    catch { /* names and ARP are best-effort */ }
                }

                live.Add(host);
                onHost(host);
                Report($"Discovering hosts ({up:N0} up)", done, targets.Count);
            }
            else
            {
                Report($"Discovering hosts ({Volatile.Read(ref liveCount):N0} up)", done, targets.Count);
            }
        }).ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();
        var hosts = live.ToArray();
        if (hosts.Length == 0)
        {
            progress?.Report(new ScanProgress("Scanning ports", 0, 0));
            return;
        }

        var totalProbes = hosts.Length * ports.Count;
        var finishedProbes = 0;
        Interlocked.Exchange(ref lastReport, 0);
        Report("Scanning ports", 0, totalProbes);

        using var gate = new SemaphoreSlim(options.Concurrency, options.Concurrency);
        var scanOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Clamp(options.Concurrency, 1, 8),
            CancellationToken = cancellationToken
        };

        await Parallel.ForEachAsync(hosts, scanOptions, async (host, token) =>
        {
            try
            {
                var open = await PortScanner.ScanAsync(
                    host.Address,
                    ports,
                    options.TimeoutMs,
                    gate,
                    options.GrabBanners,
                    token,
                    () =>
                    {
                        var done = Interlocked.Increment(ref finishedProbes);
                        Report("Scanning ports", done, totalProbes);
                    }).ConfigureAwait(false);

                lock (host.Ports)
                {
                    host.Ports.Clear();
                    host.Ports.AddRange(open);
                }

                onHost(host);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                onHost(host);
            }
        }).ConfigureAwait(false);

        progress?.Report(new ScanProgress("Scanning ports", totalProbes, totalProbes));
    }
}
