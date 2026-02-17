# Invoke-PreDeliveryCleanup

A PowerShell script that audits, cleans, and verifies removal of all developer and company identity remnants from a Windows system before delivering hardware to customers.

## The Problem

When you develop software on Windows machines that ship to customers, dozens of identity artifacts accumulate across the OS — WiFi networks you connected to, USB devices you plugged in, credentials you cached, browser history, your username baked into registry keys, event logs full of your SID, and much more. Missing even one of these can leak your internal infrastructure details, network topology, or personal information to the customer.

This script systematically finds and removes all of it.

## What It Cleans

The script covers 30 categories organized into five areas:

### Network & Connectivity

|Category                  |What’s Found                             |Where It Lives                                   |
|--------------------------|-----------------------------------------|-------------------------------------------------|
|WiFi Profiles             |SSIDs, passwords, connection history     |`netsh wlan`, `HKLM:\...\NetworkList\Profiles`   |
|Network Location Awareness|Network names, DNS suffixes, gateway MACs|`HKLM:\...\NetworkList\Signatures`, NLA cache    |
|Mapped Drives             |UNC paths, drive letter mappings         |`MountPoints2`, `net use`                        |
|RDP History               |Server addresses, connection defaults    |`HKCU:\...\Terminal Server Client`, `Default.rdp`|
|VPN Connections           |Server addresses, connection configs     |`rasphone.pbk`, `Get-VpnConnection`              |
|Stored Credentials        |Windows & web credentials, SMB sessions  |Credential Manager (`cmdkey`), `net use`         |
|DNS Cache                 |Resolved hostnames                       |`Get-DnsClientCache`                             |
|ARP Cache                 |IP-to-MAC mappings from your network     |`Get-NetNeighbor`                                |

### Device History

|Category     |What’s Found                               |Where It Lives                            |
|-------------|-------------------------------------------|------------------------------------------|
|USB Devices  |Every USB device ever connected            |`HKLM:\...\Enum\USBSTOR`, `MountedDevices`|
|Bluetooth    |Paired device names and addresses          |`HKLM:\...\BTHPORT\Parameters\Devices`    |
|Printers     |Non-default printers you installed         |`Get-Printer`                             |
|SetupAPI Logs|Full device install history with timestamps|`%SystemRoot%\INF\setupapi.*.log`         |

### User & Identity Artifacts

|Category             |What’s Found                            |Where It Lives                       |
|---------------------|----------------------------------------|-------------------------------------|
|Registered Owner     |Your name/company in system properties  |`HKLM:\...\Windows NT\CurrentVersion`|
|OEM Information      |Manufacturer, support URL, phone        |`HKLM:\...\OEMInformation`           |
|Computer Description |Machine description string              |`LanmanServer\Parameters\srvcomment` |
|Environment Variables|Paths or values containing company names|System/User environment              |

### Shell & Application Artifacts

|Category          |What’s Found                          |Where It Lives                               |
|------------------|--------------------------------------|---------------------------------------------|
|Recent Files      |Recently opened file shortcuts        |`%APPDATA%\...\Recent`                       |
|Explorer MRU      |Typed paths, Run history, file dialogs|Multiple registry keys under `Explorer`      |
|Jump Lists        |Taskbar/Start menu recent items       |`AutomaticDestinations`, `CustomDestinations`|
|Prefetch          |Record of every .exe you’ve run       |`%SystemRoot%\Prefetch\*.pf`                 |
|Thumbnail Cache   |Cached image thumbnails               |`thumbcache_*.db`, `iconcache_*.db`          |
|Activity History  |Windows Timeline data                 |`ActivitiesCache.db`                         |
|PowerShell History|Every command you’ve typed            |`ConsoleHost_history.txt`                    |
|Browser Data      |Edge, Chrome, Firefox profiles        |`AppData\Local\Microsoft\Edge\...` etc.      |
|Clipboard History |Copied text/images                    |Registry + in-memory                         |
|Temp Files        |Leftover temporary files              |`%TEMP%`, `%SystemRoot%\Temp`                |

### System-Level Artifacts

|Category            |What’s Found                             |Where It Lives                            |
|--------------------|-----------------------------------------|------------------------------------------|
|Event Logs          |Your username, SIDs, device names in logs|All Windows event log channels            |
|Panther Logs        |Original install/sysprep logs            |`%SystemRoot%\Panther\`                   |
|Error Reports       |Crash dumps, WER data                    |`%ProgramData%\...\WER`, minidumps        |
|BITS Jobs           |Background transfer history              |`Get-BitsTransfer`                        |
|Scheduled Tasks     |Custom tasks you may have created        |Task Scheduler (flagged, not auto-deleted)|
|Pagefile/Hibernation|Memory remnants on disk                  |`pagefile.sys`, `hiberfil.sys`            |

## Requirements

- Windows 10 or later (also works on Windows Server 2016+)
- PowerShell 5.1 or later
- **Must run as Administrator** (the script enforces this via `#Requires -RunAsAdministrator`)

## Quick Start

### 1. Audit first (no changes made)

Always start here. This shows you everything the script would clean without touching anything:

```powershell
.\Invoke-PreDeliveryCleanup.ps1 -AuditOnly
```

### 2. Run with company pattern matching

Supply your company name, domain, username, or any other identifying strings as regex patterns. The script will scan the registry, hosts file, environment variables, and user profile folders for matches:

```powershell
.\Invoke-PreDeliveryCleanup.ps1 -CompanyPatterns @('Contoso','contoso\.local','jsmith','DEVPC')
```

### 3. Skip specific sections

If certain categories don’t apply or you want to preserve them:

```powershell
.\Invoke-PreDeliveryCleanup.ps1 -SkipSections @('EventLogs','Prefetch','BrowserData')
```

### 4. Combine options

```powershell
.\Invoke-PreDeliveryCleanup.ps1 -CompanyPatterns @('MyCorp') -SkipSections @('EventLogs') -Confirm:$false
```

## Parameters

|Parameter         |Type    |Default                       |Description                                                        |
|------------------|--------|------------------------------|-------------------------------------------------------------------|
|`-AuditOnly`      |Switch  |`$false`                      |Report findings without making any changes                         |
|`-CompanyPatterns`|String[]|`@()`                         |Regex patterns to search for (company name, domain, username, etc.)|
|`-SkipSections`   |String[]|`@()`                         |Section names to skip (see valid values below)                     |
|`-LogPath`        |String  |`.\CleanupLog_<timestamp>.txt`|Path for the output log file                                       |
|`-Confirm`        |Switch  |`$true`                       |Set `-Confirm:$false` to suppress the confirmation prompt          |

### Valid section names for `-SkipSections`

`WiFi`, `NetworkProfiles`, `MappedDrives`, `RDP`, `VPN`, `Credentials`, `USBHistory`, `Bluetooth`, `Printers`, `RecentFiles`, `ExplorerMRU`, `JumpLists`, `Prefetch`, `ThumbnailCache`, `ActivityHistory`, `EventLogs`, `PowerShellHistory`, `TempFiles`, `BrowserData`, `RegisteredOwner`, `SetupApiLogs`, `PantherLogs`, `ErrorReports`, `DNSCache`, `ARPCache`, `ScheduledTasks`, `BITSJobs`, `ClipboardHistory`, `EnvironmentVariables`, `PagefileHibernation`

## How It Works

Every section follows a three-phase approach:

1. **Find** — Enumerate all artifacts in that category and display them with `[FOUND]` tags
1. **Clean** — Delete, truncate, or clear each artifact (skipped in audit mode)
1. **Verify** — Confirm the artifact is gone, reporting `[CLEAN]` on success or `[ERROR]` if something remains

At the end, the script prints a summary of total issues found, cleaned, and remaining, then writes a full log to disk.

### Safety Measures

Some items are intentionally **not** auto-deleted because removing them blindly could break the system:

- **Scheduled tasks** — Listed for your review but not deleted automatically
- **Environment variables** — Matches are reported; you decide what to change
- **User profile folders** — Flagged if they match company patterns; should be removed via account deletion or sysprep
- **TCP/IP hostname/domain** — Reported but not changed; use `Rename-Computer` or sysprep instead
- **MountedDevices / USBSTOR** — Attempted but may require offline registry editing for full removal due to system locks

## Post-Cleanup Recommendations

The script prints these at the end of every run, but for reference:

1. **Rename the computer** — `Rename-Computer -NewName "YOURPRODUCTNAME" -Restart`
1. **Remove your user profile** — Delete the dev account and create a customer-facing one
1. **Run Disk Cleanup** — `cleanmgr` with all boxes checked
1. **Wipe free space** — `cipher /w:C:\` overwrites deleted file remnants so they can’t be recovered
1. **Verify system integrity** — `sfc /scannow`
1. **Sysprep for OOBE** — `C:\Windows\System32\Sysprep\sysprep.exe /oobe /generalize /shutdown` to reset the out-of-box experience
1. **Verify Windows activation** — Make sure the license isn’t tied to your org
1. **Check Device Manager** — Look for any named or company-specific devices
1. **Review the hosts file** — `C:\Windows\System32\drivers\etc\hosts`
1. **Re-run in audit mode** — `.\Invoke-PreDeliveryCleanup.ps1 -AuditOnly` to confirm everything is clean

## Recommended Workflow

```
1.  .\Invoke-PreDeliveryCleanup.ps1 -AuditOnly                          # See what exists
2.  .\Invoke-PreDeliveryCleanup.ps1 -CompanyPatterns @('YourCo')         # Clean everything
3.  Handle manual items (scheduled tasks, user profiles, hostname)
4.  Rename-Computer -NewName "PRODUCTNAME" -Restart
5.  cipher /w:C:\                                                        # Wipe free space
6.  .\Invoke-PreDeliveryCleanup.ps1 -AuditOnly                          # Verify clean
7.  sysprep /oobe /generalize /shutdown                                  # Final OOBE prep
```

## Log Output

Every run generates a timestamped log file (default: `.\CleanupLog_YYYYMMDD_HHmmss.txt`) containing all findings, actions taken, and verification results. The console output is color-coded:

- **Cyan** — Section headers
- **Yellow** — Found artifacts
- **Green** — Successfully cleaned
- **Magenta** — Verification results
- **Red** — Errors or failures

## License

MIT — use, modify, and distribute freely.