# NetScope 1.0.1

NetScope is a standalone Windows desktop scanner for networks you own or are authorized to test. It discovers live hosts, scans TCP ports with a normal connect (no raw packets and no administrator account), and lists what it found.

More apps: [coreydblackwell.com/apps](https://www.coreydblackwell.com/apps/).

## Requirements

- **Run the app:** Windows 10 or Windows 11, 64-bit. The published `NetScope.exe` is a self-contained .NET 8 build, so the PC does not need a separate .NET install or an installer.
- **Build from source:** the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0). On Windows, `.\build.ps1` runs the tests and publishes the exe. On Linux, `./build.sh` does the same. The WinForms project targets `net8.0-windows`; `EnableWindowsTargeting` is already set so that project can compile on Linux and is published for `win-x64`.
- **Tests:** `dotnet test` runs on Windows or Linux. Scanning, Remote Desktop, SSH launch, and SMB share listing are Windows features. The core library and the unit tests do not need Windows.

## Changelog

### 1.0.1

- The results grid keeps visible column headers: **IP Address**, **Hostname**, **MAC Address**, **Vendor**, **Latency (ms)**, and **Open Ports**. Click a header to sort.
- CSV and JSON export use those same names. Export also includes **DNS Name**, **NetBIOS Name**, **mDNS Name**, and **Banners**.
- The port list and the SMB share list keep their own headers (**Port**, **Service**, **Banner**, and **Share Name**, **Type**, **Admin**, **Remark**).
- `NetScope.exe --demo` fills the window with fictional hosts for screenshots. It does not scan, and the flag is not shown in the window.

The download is a single `NetScope.exe` for Windows 10/11 x64. It does not need an installer or a preinstalled .NET runtime.

## Run

1. Copy `NetScope.exe` anywhere.
2. Double-click it.
3. Confirm the pre-filled subnet, or type a target, then click **Scan**.

The yellow bar in the window is the rule of use: scan only networks you own or are authorized to test. Unauthorized scanning may be illegal.

### Targets

| Input | Meaning |
| --- | --- |
| `192.168.1.0/24` | CIDR subnet. `/31` keeps both addresses, `/32` is one host, and shorter prefixes skip the network and broadcast addresses. |
| `192.168.1.10-50` | Last-octet range, inclusive. |
| `192.168.1.10-192.168.1.50` | Full IPv4 range, inclusive. |
| `192.168.1.10` | One host. |

On startup the target box is filled with this PC's subnet, taken from the active IPv4 adapter (a private adapter with a gateway is preferred over link-local). **My subnet** fills it again. A scan is limited to 65,536 hosts. IPv4 only.

### Ports

- **Common (top 100)** is the default. It includes 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080, and the rest of the usual top 100 TCP ports.
- **All ports (1-65535)**.
- **Custom**, for example `22,80,443,8000-8010`.

Concurrency defaults to 128 simultaneous connections (1–512). The connect timeout defaults to 400 ms (50–10000). Scans that would attempt more than 250,000 connections ask for confirmation first. Cancel stops the work already queued.

Host discovery pings with ICMP and, in parallel, tries a short TCP connect to 445, 80, 443, 22, 139, 135, 3389, and 8080. Hosts that answer neither are not port-scanned. Open ports are found with a TCP connect. When a service sends a banner, NetScope reads a short one and uses an `SSH-` banner to recognize SSH on any port.

### Results

The table headers stay visible: **IP Address**, **Hostname**, **MAC Address**, **Vendor**, **Latency (ms)**, and **Open Ports** (with common service names). Click a header to sort. Filter matches IP, hostname, MAC, vendor, or port. Select a row for names (reverse DNS, NetBIOS, mDNS/LLMNR), the port list, and actions.

MAC addresses come from ARP (`SendARP` on Windows) for hosts that answer on the local link. The vendor comes from an embedded IEEE OUI listing. Randomized addresses are labeled **Locally administered**.

**Export CSV**, **Export JSON**, and **Copy IPs** use the rows currently shown. Right-click a host to copy the IP, hostname, MAC, or the whole row. Ctrl+C copies the selected IP addresses.

## Connect

When Remote Desktop (TCP 3389) is open, **Connect RDP** and the right-click menu run:

```text
mstsc.exe /v:<host>:<port>
```

The host is a resolved name when it is safe to pass on a command line, otherwise the IP address.

When TCP 22 is open, or any open port returns an `SSH-` banner, **Connect SSH** asks for an optional username (the last one you used is filled in) and starts a new window:

- Windows Terminal, when `wt.exe` and OpenSSH are both installed: `wt.exe -- ssh <user>@<host> -p <port>`
- otherwise a new console: `cmd.exe` starts `ssh <user>@<host> -p <port>`
- if `ssh.exe` is missing, PuTTY when it is installed: `putty.exe -ssh <host> -P <port> -l <user>`
- if neither client exists, a short message explains how to install OpenSSH or PuTTY

Leave the username blank to let the SSH client use your Windows account. NetScope never asks for an SSH password and does not put one in the command line. The last username is stored in `%AppData%\NetScope\settings.json`. Passwords are not.

## SMB shares

When TCP 445 or 139 is open, **List shares** (details pane and right-click) calls `NetShareEnum` and shows the share name, type (disk, printer, device, IPC), remark, and an admin flag. Admin shares such as `C$`, `ADMIN$`, and `IPC$` are hidden by default. Clear **Hide admin shares** to show them; they stay marked Admin.

The call uses your current Windows sign-in and gives up after 8 seconds. If access is denied, **Retry with different credentials…** opens the standard Windows credential dialog. Those credentials are used only for that connection (`WNetAddConnection2` to `\\host\IPC$`), the IPC connection is dropped afterward, and the password is not written to settings or to a command line. The dialog is shown without a save checkbox.

For a disk share, **Open in Explorer** runs `explorer.exe \\host\share`, and **Copy path** copies that UNC path.

## Build

Requires the .NET 8 SDK on Windows 10/11 x64, or the .NET 8 SDK on Linux with the Windows targeting pack enabled in this repo.

```bash
./build.sh
```

On Windows:

```powershell
.\build.ps1
```

Both commands run the tests, then publish a self-contained single-file exe to `artifacts/publish/NetScope.exe` and write `artifacts/NetScope-1.0.1-win-x64.zip` (the exe plus this README).

To build only the exe:

```bash
dotnet publish src/NetScope/NetScope.csproj -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:EnableCompressionInSingleFile=true
```

On Windows you can also run from source without publishing:

```powershell
dotnet run --project src/NetScope/NetScope.csproj
```

`dotnet test` runs on Linux or Windows. The WinForms project targets `net8.0-windows`. Building that project on Linux needs `EnableWindowsTargeting` (already set in the project file) and is published for `win-x64`.

## Tests

- CIDR, last-octet ranges, full ranges, single addresses, and the 65,536-host cap
- Port lists, ranges, the top 100 ports, and 1–65535
- TCP connect scan against a local listener, including an SSH banner and cancellation
- Discovery when ICMP does not answer
- RDP, OpenSSH, Windows Terminal, and PuTTY command lines
- SMB share types, the admin-share filter, UNC paths, and the non-Windows error
- NetBIOS and mDNS name parsing, OUI lookup, CSV/JSON export, and subnet math

## Layout

- `src/NetScope.Core` — parsing, scanning, names, OUI data, export, connect commands, SMB
- `src/NetScope` — WinForms UI
- `tests/NetScope.Tests` — xUnit tests
- `src/NetScope.Core/Oui/oui.txt` — vendor prefixes derived from the IEEE public OUI listing

## Limitations

- TCP connect only. There is no SYN scan, UDP scan, or raw packet work. A connect completes the handshake, so the target can log it.
- ICMP can be blocked. A host is also missed when it drops the fallback ports.
- ARP/MAC works for hosts on the local link. `SendARP` is a Windows API. Off-subnet hosts will not have a MAC.
- The OUI file is the IEEE public listing embedded in the exe. A prefix that is not in that list, or a locally administered address, has no vendor name.
- Reverse DNS, NetBIOS node status, and a best-effort mDNS (UDP 5353) / LLMNR (UDP 5355) PTR query are attempted with a short timeout. Many hosts answer none of them.
- SMB listing, the credential dialog, Remote Desktop, and SSH launch need Windows and the corresponding client (`mstsc.exe`, `ssh.exe` / Windows Terminal, or PuTTY). `NetShareEnum` cannot be cancelled; after the timeout NetScope stops waiting, but the native call may still finish in the background.
- Passwords typed into the Windows credential dialog or into the SSH window are not stored by NetScope. A .NET string used for the SMB call can remain on the heap until garbage collection.
- The credential dialog does not show a save checkbox. Windows itself is not asked to persist the credential.
- IPv4 only. One scan accepts at most 65,536 hosts.
- The first launch of the single-file exe unpacks native libraries into a temporary folder. That can make the first start slower, and some antivirus tools scan it.
