using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetScope.Core;

public static class PortScanner
{
    public static async Task<IReadOnlyList<OpenPort>> ScanAsync(
        IPAddress address,
        IReadOnlyList<int> ports,
        int timeoutMs,
        int concurrency,
        bool grabBanners,
        CancellationToken cancellationToken)
    {
        ScanLimits.ValidateConcurrency(concurrency);
        using var gate = new SemaphoreSlim(concurrency, concurrency);
        return await ScanAsync(address, ports, timeoutMs, gate, grabBanners, cancellationToken).ConfigureAwait(false);
    }

    public static async Task<IReadOnlyList<OpenPort>> ScanAsync(
        IPAddress address,
        IReadOnlyList<int> ports,
        int timeoutMs,
        SemaphoreSlim gate,
        bool grabBanners,
        CancellationToken cancellationToken,
        Action? onProbeFinished = null)
    {
        ScanLimits.ValidateTimeout(timeoutMs);
        var open = new ConcurrentBag<OpenPort>();
        const int batchSize = 128;
        for (var offset = 0; offset < ports.Count; offset += batchSize)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = Math.Min(batchSize, ports.Count - offset);
            var tasks = new Task[count];
            for (var i = 0; i < count; i++)
            {
                var port = ports[offset + i];
                tasks[i] = ProbeAsync(address, port, timeoutMs, grabBanners, gate, open, cancellationToken, onProbeFinished);
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);
        }

        return open.OrderBy(p => p.Number).ToArray();
    }

    private static async Task ProbeAsync(
        IPAddress address,
        int port,
        int timeoutMs,
        bool grabBanners,
        SemaphoreSlim gate,
        ConcurrentBag<OpenPort> open,
        CancellationToken cancellationToken,
        Action? onProbeFinished)
    {
        var acquired = false;
        TcpClient? client = null;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            acquired = true;
            client = new TcpClient { NoDelay = true };
            var connect = client.ConnectAsync(address, port);
            var finished = await Task.WhenAny(connect, Task.Delay(timeoutMs, cancellationToken)).ConfigureAwait(false);
            if (finished != connect)
            {
                Observe(connect);
                client.Dispose();
                client = null;
                if (cancellationToken.IsCancellationRequested)
                    throw new OperationCanceledException(cancellationToken);
                return;
            }

            await connect.ConfigureAwait(false);
            string? banner = null;
            if (grabBanners)
                banner = await ReadBannerAsync(client, cancellationToken).ConfigureAwait(false);
            var normalized = BannerClassifier.Normalize(banner);
            open.Add(new OpenPort(port, ServiceNames.Resolve(port, normalized), normalized, BannerClassifier.IsSsh(normalized)));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // Refused, reset, or unreachable. The port is not reported as open.
        }
        finally
        {
            client?.Dispose();
            if (acquired)
                gate.Release();
            onProbeFinished?.Invoke();
        }
    }

    private static async Task<string?> ReadBannerAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(ScanLimits.BannerTimeoutMs);
        try
        {
            var stream = client.GetStream();
            var buffer = new byte[256];
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), timeout.Token).ConfigureAwait(false);
            if (read <= 0)
                return null;
            return Encoding.ASCII.GetString(buffer, 0, read);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    internal static void Observe(Task task)
    {
        _ = task.ContinueWith(
            static t => { _ = t.Exception; },
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }
}
