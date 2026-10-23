namespace NetScope.Core;

public static class ServiceNames
{
    private static readonly Dictionary<int, string> Names = new()
    {
        [7] = "echo",
        [9] = "discard",
        [13] = "daytime",
        [21] = "ftp",
        [22] = "ssh",
        [23] = "telnet",
        [25] = "smtp",
        [26] = "rsftp",
        [37] = "time",
        [53] = "domain",
        [79] = "finger",
        [80] = "http",
        [81] = "http",
        [88] = "kerberos",
        [106] = "pop3pw",
        [110] = "pop3",
        [111] = "rpcbind",
        [113] = "ident",
        [119] = "nntp",
        [135] = "msrpc",
        [139] = "netbios-ssn",
        [143] = "imap",
        [144] = "news",
        [179] = "bgp",
        [199] = "smux",
        [389] = "ldap",
        [427] = "svrloc",
        [443] = "https",
        [444] = "snpp",
        [445] = "microsoft-ds",
        [465] = "smtps",
        [513] = "login",
        [514] = "shell",
        [515] = "printer",
        [543] = "klogin",
        [544] = "kshell",
        [548] = "afp",
        [554] = "rtsp",
        [587] = "submission",
        [631] = "ipp",
        [636] = "ldaps",
        [646] = "ldp",
        [873] = "rsync",
        [990] = "ftps",
        [993] = "imaps",
        [995] = "pop3s",
        [1025] = "NFS-or-IIS",
        [1026] = "LSA-or-nterm",
        [1027] = "IIS",
        [1029] = "ms-lsa",
        [1110] = "nfsd-status",
        [1433] = "ms-sql-s",
        [1434] = "ms-sql-m",
        [1521] = "oracle",
        [1720] = "h323q931",
        [1723] = "pptp",
        [1755] = "wms",
        [1883] = "mqtt",
        [1900] = "upnp",
        [2000] = "cisco-sccp",
        [2001] = "dc",
        [2049] = "nfs",
        [2121] = "ccproxy-ftp",
        [2375] = "docker",
        [2717] = "pn-requester",
        [3000] = "http-alt",
        [3128] = "squid-http",
        [3268] = "globalcat",
        [3269] = "globalcat-ssl",
        [3306] = "mysql",
        [3389] = "ms-wbt-server",
        [3986] = "mapper-ws",
        [4899] = "radmin",
        [5000] = "upnp",
        [5009] = "airport-admin",
        [5051] = "ida-agent",
        [5060] = "sip",
        [5101] = "admdog",
        [5190] = "aol",
        [5357] = "wsdapi",
        [5432] = "postgresql",
        [5631] = "pcanywheredata",
        [5666] = "nrpe",
        [5672] = "amqp",
        [5800] = "vnc-http",
        [5900] = "vnc",
        [5901] = "vnc",
        [5985] = "winrm",
        [5986] = "winrm-https",
        [6000] = "x11",
        [6001] = "x11",
        [6379] = "redis",
        [6443] = "kubernetes",
        [6646] = "unknown",
        [7070] = "realserver",
        [8000] = "http-alt",
        [8008] = "http-alt",
        [8009] = "ajp13",
        [8080] = "http-proxy",
        [8081] = "blackice-icecap",
        [8443] = "https-alt",
        [8883] = "secure-mqtt",
        [8888] = "sun-answerbook",
        [9100] = "jetdirect",
        [9200] = "elasticsearch",
        [9999] = "abyss",
        [10000] = "snet-sensor-mgmt",
        [11211] = "memcached",
        [27017] = "mongodb",
        [32768] = "filenet-tms"
    };

    public static string ForPort(int port) => Names.TryGetValue(port, out var name) ? name : "unknown";

    public static string Resolve(int port, string? banner)
    {
        if (BannerClassifier.IsSsh(banner))
            return "ssh";
        if (!string.IsNullOrWhiteSpace(banner))
        {
            var text = banner.TrimStart();
            if (text.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
                return port is 443 or 8443 ? "https" : "http";
            if (text.StartsWith("220", StringComparison.Ordinal) && text.Contains("FTP", StringComparison.OrdinalIgnoreCase))
                return "ftp";
            if (text.StartsWith("220", StringComparison.Ordinal) && text.Contains("SMTP", StringComparison.OrdinalIgnoreCase))
                return "smtp";
        }

        return ForPort(port);
    }
}
