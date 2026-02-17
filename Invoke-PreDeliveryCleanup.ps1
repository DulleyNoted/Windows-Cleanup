#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Pre-delivery system identity cleanup script.

.DESCRIPTION
    Audits, cleans, and verifies removal of all developer/company identity
    remnants from a Windows system before customer delivery. Covers network
    profiles, device history, user artifacts, shell MRU lists, credentials,
    logs, and more.

    Run with -AuditOnly to see what would be cleaned without making changes.
    Run with -CompanyPatterns to also search for company-specific strings.

.PARAMETER AuditOnly
    When set, the script only reports findings without deleting anything.

.PARAMETER CompanyPatterns
    Array of regex patterns to search for (company name, domain, username, etc.)
    Example: -CompanyPatterns @('Contoso','contoso\.com','jsmith')

.PARAMETER SkipSections
    Array of section names to skip. Valid values:
    WiFi, NetworkProfiles, MappedDrives, RDP, VPN, Credentials,
    USBHistory, Bluetooth, Printers, RecentFiles, ExplorerMRU,
    JumpLists, Prefetch, ThumbnailCache, ActivityHistory, EventLogs,
    PowerShellHistory, TempFiles, BrowserData, RegisteredOwner,
    SetupApiLogs, PantherLogs, ErrorReports, DNSCache, ARPCache,
    ScheduledTasks, BITSJobs, ClipboardHistory, EnvironmentVariables,
    PagefileHibernation

.PARAMETER LogPath
    Path to write the cleanup log. Defaults to .\CleanupLog_<timestamp>.txt

.EXAMPLE
    .\Invoke-PreDeliveryCleanup.ps1 -AuditOnly
    .\Invoke-PreDeliveryCleanup.ps1 -CompanyPatterns @('MyCorp','mycorp\.local','devuser')
    .\Invoke-PreDeliveryCleanup.ps1 -SkipSections @('EventLogs','Prefetch')
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$AuditOnly,

    [string[]]$CompanyPatterns = @(),

    [ValidateSet(
        'WiFi','NetworkProfiles','MappedDrives','RDP','VPN','Credentials',
        'USBHistory','Bluetooth','Printers','RecentFiles','ExplorerMRU',
        'JumpLists','Prefetch','ThumbnailCache','ActivityHistory','EventLogs',
        'PowerShellHistory','TempFiles','BrowserData','RegisteredOwner',
        'SetupApiLogs','PantherLogs','ErrorReports','DNSCache','ARPCache',
        'ScheduledTasks','BITSJobs','ClipboardHistory','EnvironmentVariables',
        'PagefileHibernation'
    )]
    [string[]]$SkipSections = @(),

    [string]$LogPath = ".\CleanupLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

# ============================================================================
# GLOBALS & HELPERS
# ============================================================================
$ErrorActionPreference = 'SilentlyContinue'
$script:LogEntries = [System.Collections.Generic.List[string]]::new()
$script:IssuesFound = 0
$script:IssuesCleaned = 0
$script:IssuesRemaining = 0

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','FOUND','CLEAN','VERIFY','WARN','ERROR','SECTION')][string]$Level = 'INFO')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $prefix = switch ($Level) {
        'SECTION' { "`n{'='*70}`n" }
        'FOUND'   { '  [FOUND]   ' }
        'CLEAN'   { '  [CLEAN]   ' }
        'VERIFY'  { '  [VERIFY]  ' }
        'WARN'    { '  [WARN]    ' }
        'ERROR'   { '  [ERROR]   ' }
        default   { '  [INFO]    ' }
    }
    $line = if ($Level -eq 'SECTION') { "$prefix $Message`n$('='*70)" } else { "$timestamp $prefix$Message" }
    Write-Host $line -ForegroundColor $(switch ($Level) {
        'SECTION' { 'Cyan' }
        'FOUND'   { 'Yellow' }
        'CLEAN'   { 'Green' }
        'VERIFY'  { 'Magenta' }
        'WARN'    { 'DarkYellow' }
        'ERROR'   { 'Red' }
        default   { 'Gray' }
    })
    $script:LogEntries.Add($line)
}

function Test-ShouldProcess {
    param([string]$Section)
    if ($Section -in $SkipSections) {
        Write-Log "Skipping section: $Section" -Level WARN
        return $false
    }
    return $true
}

function Remove-RegistryKeyIfExists {
    param([string]$Path, [string]$Description)
    if (Test-Path $Path) {
        $script:IssuesFound++
        Write-Log "$Description : $Path" -Level FOUND
        if (-not $AuditOnly) {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $Path)) {
                Write-Log "Removed: $Path" -Level CLEAN
                $script:IssuesCleaned++
            } else {
                Write-Log "FAILED to remove: $Path" -Level ERROR
                $script:IssuesRemaining++
            }
        }
    }
}

function Remove-RegistryValueIfExists {
    param([string]$Path, [string]$Name, [string]$Description)
    $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $val.$Name) {
        $script:IssuesFound++
        Write-Log "$Description : $($val.$Name)" -Level FOUND
        if (-not $AuditOnly) {
            Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
            $check = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -eq $check.$Name) {
                Write-Log "Removed value '$Name' from $Path" -Level CLEAN
                $script:IssuesCleaned++
            } else {
                Write-Log "FAILED to remove value '$Name' from $Path" -Level ERROR
                $script:IssuesRemaining++
            }
        }
    }
}

function Remove-FilesFromPath {
    param([string]$Path, [string]$Filter = '*', [string]$Description, [switch]$Recurse)
    if (Test-Path $Path) {
        $params = @{ Path = $Path; Filter = $Filter; File = $true; ErrorAction = 'SilentlyContinue' }
        if ($Recurse) { $params.Recurse = $true }
        $files = @(Get-ChildItem @params)
        if ($files.Count -gt 0) {
            $script:IssuesFound++
            Write-Log "$Description : $($files.Count) file(s) in $Path" -Level FOUND
            if (-not $AuditOnly) {
                $files | Remove-Item -Force -ErrorAction SilentlyContinue
                $remaining = @(Get-ChildItem @params)
                $removed = $files.Count - $remaining.Count
                Write-Log "Removed $removed / $($files.Count) file(s)" -Level CLEAN
                if ($remaining.Count -eq 0) { $script:IssuesCleaned++ } else { $script:IssuesRemaining++ }
            }
        }
    }
}

# ============================================================================
# SECTION FUNCTIONS
# ============================================================================

function Clean-WiFiProfiles {
    if (-not (Test-ShouldProcess 'WiFi')) { return }
    Write-Log 'WiFi Profiles' -Level SECTION

    # Stored WiFi profiles via netsh
    $profiles = @(netsh wlan show profiles 2>$null |
        Select-String ':\s+(.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })

    if ($profiles.Count -gt 0) {
        $script:IssuesFound++
        Write-Log "Found $($profiles.Count) WiFi profile(s):" -Level FOUND
        $profiles | ForEach-Object { Write-Log "  - $_" -Level INFO }
        if (-not $AuditOnly) {
            foreach ($p in $profiles) {
                netsh wlan delete profile name="$p" 2>$null | Out-Null
            }
            $remaining = @(netsh wlan show profiles 2>$null |
                Select-String ':\s+(.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })
            Write-Log "Removed $($profiles.Count - $remaining.Count) / $($profiles.Count) WiFi profiles" -Level CLEAN
            if ($remaining.Count -eq 0) { $script:IssuesCleaned++ } else { $script:IssuesRemaining++ }
        }
    } else {
        Write-Log 'No WiFi profiles found' -Level INFO
    }

    # Registry: WiFi network list profiles
    $nlaPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache\Intranet',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache\IntranetProbing'
    )
    foreach ($nlaPath in $nlaPaths) {
        if (Test-Path $nlaPath) {
            $subkeys = @(Get-ChildItem $nlaPath -ErrorAction SilentlyContinue)
            if ($subkeys.Count -gt 0) {
                $script:IssuesFound++
                Write-Log "Network list entries in $nlaPath : $($subkeys.Count)" -Level FOUND
                $subkeys | ForEach-Object {
                    $name = (Get-ItemProperty $_.PSPath -Name 'ProfileName' -ErrorAction SilentlyContinue).ProfileName
                    if ($name) { Write-Log "  - $name" -Level INFO }
                }
                if (-not $AuditOnly) {
                    $subkeys | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                    $rem = @(Get-ChildItem $nlaPath -ErrorAction SilentlyContinue)
                    if ($rem.Count -eq 0) { Write-Log "Cleared $nlaPath" -Level CLEAN; $script:IssuesCleaned++ }
                    else { Write-Log "Some entries remain in $nlaPath" -Level ERROR; $script:IssuesRemaining++ }
                }
            }
        }
    }
}

function Clean-NetworkProfiles {
    if (-not (Test-ShouldProcess 'NetworkProfiles')) { return }
    Write-Log 'Network Location Awareness (NLA) Profiles' -Level SECTION

    # Firewall profiles can reveal network names
    $fwPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\{A4C01F0E-6B56-4be5-8E74-1C7A2FA6BE56}'
    Remove-RegistryKeyIfExists $fwPath 'Group Policy network history'

    # Network setup info
    $tcpipParams = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    foreach ($val in @('Domain','DhcpDomain','Hostname','NV Hostname')) {
        $current = (Get-ItemProperty -Path $tcpipParams -Name $val -ErrorAction SilentlyContinue).$val
        if ($current) {
            Write-Log "TCP/IP Parameter '$val' = $current" -Level FOUND
            $script:IssuesFound++
        }
    }
    Write-Log 'Note: Hostname/Domain should be set to customer values via Rename-Computer / sysprep' -Level WARN
}

function Clean-MappedDrives {
    if (-not (Test-ShouldProcess 'MappedDrives')) { return }
    Write-Log 'Mapped Drives & Network Shares' -Level SECTION

    # Current mapped drives
    $mapped = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayRoot -and $_.DisplayRoot -match '^\\\\' })
    if ($mapped.Count -gt 0) {
        $script:IssuesFound++
        Write-Log "Active mapped drives:" -Level FOUND
        $mapped | ForEach-Object { Write-Log "  $($_.Name): -> $($_.DisplayRoot)" -Level INFO }
        if (-not $AuditOnly) {
            $mapped | ForEach-Object { net use "$($_.Name):" /delete /y 2>$null | Out-Null }
            Write-Log 'Disconnected mapped drives' -Level CLEAN
            $script:IssuesCleaned++
        }
    }

    # MountPoints2 in all user hives
    $userHives = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '_Classes$' -and $_.Name -notmatch '\.DEFAULT' }
    foreach ($hive in $userHives) {
        $mp2Path = "Registry::$($hive.Name)\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
        if (Test-Path $mp2Path) {
            $entries = @(Get-ChildItem $mp2Path -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match '^#' })
            if ($entries.Count -gt 0) {
                $script:IssuesFound++
                Write-Log "MountPoints2 network entries ($($hive.PSChildName)): $($entries.Count)" -Level FOUND
                $entries | ForEach-Object {
                    $unc = $_.PSChildName -replace '#','\' -replace '#','\'
                    Write-Log "  - $unc" -Level INFO
                }
                if (-not $AuditOnly) {
                    $entries | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log 'Removed MountPoints2 network entries' -Level CLEAN
                    $script:IssuesCleaned++
                }
            }
        }
    }

    # Network MRU
    foreach ($hive in $userHives) {
        $netMru = "Registry::$($hive.Name)\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU"
        Remove-RegistryKeyIfExists $netMru "Map Network Drive MRU ($($hive.PSChildName))"
    }
}

function Clean-RDP {
    if (-not (Test-ShouldProcess 'RDP')) { return }
    Write-Log 'RDP Connection History' -Level SECTION

    # Registry MRU
    foreach ($hive in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '_Classes$|\.DEFAULT' })) {
        $rdpPath = "Registry::$($hive.Name)\Software\Microsoft\Terminal Server Client"
        if (Test-Path $rdpPath) {
            $servers = $rdpPath + '\Servers'
            $default = $rdpPath + '\Default'
            Remove-RegistryKeyIfExists $servers "RDP server history ($($hive.PSChildName))"
            Remove-RegistryKeyIfExists $default "RDP default connection ($($hive.PSChildName))"
        }
    }

    # Default.rdp files
    $userProfiles = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    foreach ($profile in $userProfiles) {
        $rdpFile = Join-Path $profile.FullName 'Documents\Default.rdp'
        if (Test-Path $rdpFile) {
            $script:IssuesFound++
            Write-Log "Default.rdp found: $rdpFile" -Level FOUND
            if (-not $AuditOnly) {
                Remove-Item $rdpFile -Force
                if (-not (Test-Path $rdpFile)) { Write-Log "Removed $rdpFile" -Level CLEAN; $script:IssuesCleaned++ }
                else { $script:IssuesRemaining++ }
            }
        }
    }
}

function Clean-VPN {
    if (-not (Test-ShouldProcess 'VPN')) { return }
    Write-Log 'VPN Connections' -Level SECTION

    # Built-in Windows VPN (rasphone.pbk)
    $pbkLocations = @(
        "$env:APPDATA\Microsoft\Network\Connections\Pbk\rasphone.pbk",
        "$env:ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk"
    )
    foreach ($pbk in $pbkLocations) {
        if (Test-Path $pbk) {
            $script:IssuesFound++
            $content = Get-Content $pbk -Raw
            $entries = ([regex]::Matches($content, '^\[(.+)\]', 'Multiline')).Value
            Write-Log "VPN phonebook: $pbk ($($entries.Count) entries)" -Level FOUND
            $entries | ForEach-Object { Write-Log "  - $_" -Level INFO }
            if (-not $AuditOnly) {
                Remove-Item $pbk -Force
                if (-not (Test-Path $pbk)) { Write-Log "Removed $pbk" -Level CLEAN; $script:IssuesCleaned++ }
                else { $script:IssuesRemaining++ }
            }
        }
    }

    # Windows VPN profiles via PowerShell
    $vpnConns = @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue) +
                @(Get-VpnConnection -ErrorAction SilentlyContinue)
    foreach ($vpn in $vpnConns) {
        $script:IssuesFound++
        Write-Log "VPN connection: $($vpn.Name) -> $($vpn.ServerAddress)" -Level FOUND
        if (-not $AuditOnly) {
            Remove-VpnConnection -Name $vpn.Name -Force -AllUserConnection -ErrorAction SilentlyContinue
            Remove-VpnConnection -Name $vpn.Name -Force -ErrorAction SilentlyContinue
            Write-Log "Removed VPN: $($vpn.Name)" -Level CLEAN
            $script:IssuesCleaned++
        }
    }
}

function Clean-Credentials {
    if (-not (Test-ShouldProcess 'Credentials')) { return }
    Write-Log 'Credential Manager' -Level SECTION

    # Windows and Web credentials
    $credOutput = cmdkey /list 2>$null
    $targets = @($credOutput | Select-String 'Target:\s+(.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })
    if ($targets.Count -gt 0) {
        $script:IssuesFound++
        Write-Log "Stored credentials: $($targets.Count)" -Level FOUND
        $targets | ForEach-Object { Write-Log "  - $_" -Level INFO }
        if (-not $AuditOnly) {
            foreach ($t in $targets) {
                cmdkey /delete:"$t" 2>$null | Out-Null
            }
            $remaining = @(cmdkey /list 2>$null | Select-String 'Target:\s+(.+)$')
            Write-Log "Removed $($targets.Count - $remaining.Count) / $($targets.Count) credentials" -Level CLEAN
            if ($remaining.Count -eq 0) { $script:IssuesCleaned++ } else { $script:IssuesRemaining++ }
        }
    }

    # Cached SMB sessions
    $smbSessions = @(net use 2>$null | Select-String '\\\\')
    if ($smbSessions.Count -gt 0) {
        $script:IssuesFound++
        Write-Log "Active SMB sessions: $($smbSessions.Count)" -Level FOUND
        if (-not $AuditOnly) {
            net use * /delete /y 2>$null | Out-Null
            Write-Log 'Disconnected all SMB sessions' -Level CLEAN
            $script:IssuesCleaned++
        }
    }
}

function Clean-USBHistory {
    if (-not (Test-ShouldProcess 'USBHistory')) { return }
    Write-Log 'USB Device History' -Level SECTION

    $usbPaths = @(
        'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR',
        'HKLM:\SYSTEM\CurrentControlSet\Enum\USB',
        'HKLM:\SYSTEM\MountedDevices'
    )

    # Enumerate USBSTOR
    $usbStorPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    if (Test-Path $usbStorPath) {
        $devices = @(Get-ChildItem $usbStorPath -Recurse -ErrorAction SilentlyContinue)
        $script:IssuesFound++
        Write-Log "USBSTOR entries: $($devices.Count)" -Level FOUND
        # Show friendly names
        $deviceNames = Get-ChildItem $usbStorPath -ErrorAction SilentlyContinue
        $deviceNames | ForEach-Object {
            Write-Log "  - $($_.PSChildName)" -Level INFO
        }
        if (-not $AuditOnly) {
            Write-Log 'Clearing USBSTOR (requires SYSTEM-level access or offline edit)...' -Level WARN
            # Attempt removal - may fail on active devices
            try {
                reg delete 'HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR' /f 2>$null | Out-Null
                if (-not (Test-Path $usbStorPath)) {
                    Write-Log 'USBSTOR cleared' -Level CLEAN
                    $script:IssuesCleaned++
                } else {
                    Write-Log 'USBSTOR partially cleared (some keys locked by system)' -Level WARN
                    $script:IssuesRemaining++
                }
            } catch {
                Write-Log "USBSTOR removal failed: $_" -Level ERROR
                $script:IssuesRemaining++
            }
        }
    }

    # MountedDevices
    $mdPath = 'HKLM:\SYSTEM\MountedDevices'
    if (Test-Path $mdPath) {
        $values = Get-ItemProperty $mdPath -ErrorAction SilentlyContinue
        $removable = $values.PSObject.Properties | Where-Object { $_.Name -match '^\\\?\?\\Volume|^\\DosDevices' }
        $script:IssuesFound++
        Write-Log "MountedDevices entries: $($removable.Count)" -Level FOUND
        Write-Log 'Note: Clearing MountedDevices may require offline registry edit for full removal' -Level WARN
    }

    # SetupAPI logs (contain device install history)
    $setupLogs = @(
        "$env:SystemRoot\INF\setupapi.dev.log",
        "$env:SystemRoot\INF\setupapi.app.log",
        "$env:SystemRoot\INF\setupapi.offline.log"
    )
    foreach ($log in $setupLogs) {
        if (Test-Path $log) {
            $size = (Get-Item $log).Length / 1KB
            $script:IssuesFound++
            Write-Log "SetupAPI log: $log ($([math]::Round($size,1)) KB)" -Level FOUND
            if (-not $AuditOnly) {
                # Truncate rather than delete (Windows expects the file to exist)
                Set-Content -Path $log -Value '' -Force -ErrorAction SilentlyContinue
                Write-Log "Truncated $log" -Level CLEAN
                $script:IssuesCleaned++
            }
        }
    }

    # Device association history
    $devContainers = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAssociations'
    Remove-RegistryKeyIfExists $devContainers 'Device association history'
}

function Clean-Bluetooth {
    if (-not (Test-ShouldProcess 'Bluetooth')) { return }
    Write-Log 'Bluetooth Device History' -Level SECTION

    $btPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices'
    if (Test-Path $btPath) {
        $btDevices = @(Get-ChildItem $btPath -ErrorAction SilentlyContinue)
        if ($btDevices.Count -gt 0) {
            $script:IssuesFound++
            Write-Log "Bluetooth paired devices: $($btDevices.Count)" -Level FOUND
            foreach ($dev in $btDevices) {
                $name = (Get-ItemProperty "$($dev.PSPath)" -Name 'Name' -ErrorAction SilentlyContinue).Name
                if ($name) {
                    # Convert byte array to string if needed
                    if ($name -is [byte[]]) { $name = [System.Text.Encoding]::UTF8.GetString($name).Trim("`0") }
                    Write-Log "  - $name ($($dev.PSChildName))" -Level INFO
                }
            }
            if (-not $AuditOnly) {
                $btDevices | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                $rem = @(Get-ChildItem $btPath -ErrorAction SilentlyContinue)
                if ($rem.Count -eq 0) { Write-Log 'Cleared Bluetooth history' -Level CLEAN; $script:IssuesCleaned++ }
                else { $script:IssuesRemaining++ }
            }
        }
    }
}

function Clean-Printers {
    if (-not (Test-ShouldProcess 'Printers')) { return }
    Write-Log 'Printer History' -Level SECTION

    $printers = @(Get-Printer -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch 'Microsoft|OneNote|PDF|XPS|Fax' })
    if ($printers.Count -gt 0) {
        $script:IssuesFound++
        Write-Log "Non-default printers: $($printers.Count)" -Level FOUND
        $printers | ForEach-Object { Write-Log "  - $($_.Name) ($($_.PortName))" -Level INFO }
        if (-not $AuditOnly) {
            $printers | ForEach-Object { Remove-Printer -Name $_.Name -ErrorAction SilentlyContinue }
            Write-Log 'Removed non-default printers' -Level CLEAN
            $script:IssuesCleaned++
        }
    }
}

function Clean-RecentFiles {
    if (-not (Test-ShouldProcess 'RecentFiles')) { return }
    Write-Log 'Recent Files & Folders' -Level SECTION

    $userProfiles = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

    foreach ($profile in $userProfiles) {
        $recentPath = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\Recent'
        Remove-FilesFromPath $recentPath -Filter '*.lnk' -Description "Recent files ($($profile.Name))" -Recurse
        Remove-FilesFromPath $recentPath -Filter '*.automaticDestinations-ms' -Description "Auto destinations ($($profile.Name))" -Recurse
        Remove-FilesFromPath $recentPath -Filter '*.customDestinations-ms' -Description "Custom destinations ($($profile.Name))" -Recurse
    }
}

function Clean-ExplorerMRU {
    if (-not (Test-ShouldProcess 'ExplorerMRU')) { return }
    Write-Log 'Explorer MRU / Typed Paths / Run History' -Level SECTION

    $mruPaths = @(
        'Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
        'Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',
        'Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU',
        'Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU',
        'Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy',
        'Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU',
        'Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
        'Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery'
    )

    foreach ($hive in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '_Classes$|\.DEFAULT' })) {
        foreach ($mru in $mruPaths) {
            $fullPath = "Registry::$($hive.Name)\$mru"
            Remove-RegistryKeyIfExists $fullPath "MRU ($($hive.PSChildName)): $mru"
        }
    }
}

function Clean-JumpLists {
    if (-not (Test-ShouldProcess 'JumpLists')) { return }
    Write-Log 'Jump Lists' -Level SECTION

    $userProfiles = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

    foreach ($profile in $userProfiles) {
        $jumpAutoPath = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations'
        $jumpCustomPath = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations'
        Remove-FilesFromPath $jumpAutoPath -Description "Jump lists auto ($($profile.Name))"
        Remove-FilesFromPath $jumpCustomPath -Description "Jump lists custom ($($profile.Name))"
    }
}

function Clean-Prefetch {
    if (-not (Test-ShouldProcess 'Prefetch')) { return }
    Write-Log 'Prefetch Files' -Level SECTION

    Remove-FilesFromPath "$env:SystemRoot\Prefetch" -Filter '*.pf' -Description 'Prefetch files'
}

function Clean-ThumbnailCache {
    if (-not (Test-ShouldProcess 'ThumbnailCache')) { return }
    Write-Log 'Thumbnail Cache' -Level SECTION

    $userProfiles = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

    foreach ($profile in $userProfiles) {
        $thumbPath = Join-Path $profile.FullName 'AppData\Local\Microsoft\Windows\Explorer'
        Remove-FilesFromPath $thumbPath -Filter 'thumbcache_*.db' -Description "Thumbnail cache ($($profile.Name))"
        Remove-FilesFromPath $thumbPath -Filter 'iconcache_*.db' -Description "Icon cache ($($profile.Name))"
    }
}

function Clean-ActivityHistory {
    if (-not (Test-ShouldProcess 'ActivityHistory')) { return }
    Write-Log 'Activity History / Timeline' -Level SECTION

    $userProfiles = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

    foreach ($profile in $userProfiles) {
        $activityPath = Join-Path $profile.FullName 'AppData\Local\ConnectedDevicesPlatform'
        if (Test-Path $activityPath) {
            $dbFiles = @(Get-ChildItem $activityPath -Filter 'ActivitiesCache.db*' -Recurse -ErrorAction SilentlyContinue)
            if ($dbFiles.Count -gt 0) {
                $script:IssuesFound++
                Write-Log "Activity history DBs ($($profile.Name)): $($dbFiles.Count)" -Level FOUND
                if (-not $AuditOnly) {
                    # Stop the service first
                    Stop-Service -Name 'CDPUserSvc*' -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 500
                    $dbFiles | Remove-Item -Force -ErrorAction SilentlyContinue
                    Write-Log 'Removed activity history databases' -Level CLEAN
                    $script:IssuesCleaned++
                }
            }
        }
    }

    # Disable activity history collection
    if (-not $AuditOnly) {
        $ahPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        if (-not (Test-Path $ahPath)) { New-Item -Path $ahPath -Force | Out-Null }
        Set-ItemProperty -Path $ahPath -Name 'EnableActivityFeed' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ahPath -Name 'PublishUserActivities' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ahPath -Name 'UploadUserActivities' -Value 0 -Type DWord -Force
        Write-Log 'Disabled activity history collection via policy' -Level CLEAN
    }
}

function Clean-EventLogs {
    if (-not (Test-ShouldProcess 'EventLogs')) { return }
    Write-Log 'Windows Event Logs' -Level SECTION

    $logs = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 })
    if ($logs.Count -gt 0) {
        $totalRecords = ($logs | Measure-Object -Property RecordCount -Sum).Sum
        $script:IssuesFound++
        Write-Log "Event logs with records: $($logs.Count) logs, $totalRecords total events" -Level FOUND
        if (-not $AuditOnly) {
            foreach ($log in $logs) {
                try {
                    [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($log.LogName)
                } catch {
                    wevtutil cl $log.LogName 2>$null
                }
            }
            $remaining = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 })
            Write-Log "Cleared $($logs.Count - $remaining.Count) / $($logs.Count) event logs" -Level CLEAN
            if ($remaining.Count -le 5) { $script:IssuesCleaned++ } else { $script:IssuesRemaining++ }
        }
    }
}

function Clean-PowerShellHistory {
    if (-not (Test-ShouldProcess 'PowerShellHistory')) { return }
    Write-Log 'PowerShell Command History' -Level SECTION

    $userProfiles = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

    foreach ($profile in $userProfiles) {
        $psHistoryPath = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (Test-Path $psHistoryPath) {
            $lines = @(Get-Content $psHistoryPath -ErrorAction SilentlyContinue).Count
            $script:IssuesFound++
            Write-Log "PS history ($($profile.Name)): $lines commands" -Level FOUND
            if (-not $AuditOnly) {
                Remove-Item $psHistoryPath -Force
                if (-not (Test-Path $psHistoryPath)) { Write-Log 'Removed PS history' -Level CLEAN; $script:IssuesCleaned++ }
                else { $script:IssuesRemaining++ }
            }
        }
    }
}

function Clean-TempFiles {
    if (-not (Test-ShouldProcess 'TempFiles')) { return }
    Write-Log 'Temporary Files' -Level SECTION

    $tempPaths = @(
        "$env:SystemRoot\Temp",
        "$env:TEMP"
    )
    # Also get per-user temp
    $userProfiles = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    foreach ($p in $userProfiles) {
        $tempPaths += Join-Path $p.FullName 'AppData\Local\Temp'
    }

    foreach ($tempPath in ($tempPaths | Select-Object -Unique)) {
        if (Test-Path $tempPath) {
            $items = @(Get-ChildItem $tempPath -ErrorAction SilentlyContinue)
            if ($items.Count -gt 0) {
                $script:IssuesFound++
                Write-Log "Temp files in $tempPath : $($items.Count) items" -Level FOUND
                if (-not $AuditOnly) {
                    $items | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                    $rem = @(Get-ChildItem $tempPath -ErrorAction SilentlyContinue)
                    Write-Log "Removed $($items.Count - $rem.Count) / $($items.Count) temp items" -Level CLEAN
                    $script:IssuesCleaned++
                }
            }
        }
    }
}

function Clean-BrowserData {
    if (-not (Test-ShouldProcess 'BrowserData')) { return }
    Write-Log 'Browser Data (Edge/Chrome/Firefox)' -Level SECTION

    $userProfiles = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

    $browserPaths = @(
        @{ Name = 'Edge';    RelPath = 'AppData\Local\Microsoft\Edge\User Data' },
        @{ Name = 'Chrome';  RelPath = 'AppData\Local\Google\Chrome\User Data' },
        @{ Name = 'Firefox'; RelPath = 'AppData\Roaming\Mozilla\Firefox\Profiles' }
    )

    foreach ($profile in $userProfiles) {
        foreach ($browser in $browserPaths) {
            $bPath = Join-Path $profile.FullName $browser.RelPath
            if (Test-Path $bPath) {
                $size = (Get-ChildItem $bPath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
                $script:IssuesFound++
                Write-Log "$($browser.Name) data ($($profile.Name)): $([math]::Round($size,1)) MB" -Level FOUND
                if (-not $AuditOnly) {
                    Remove-Item $bPath -Recurse -Force -ErrorAction SilentlyContinue
                    if (-not (Test-Path $bPath)) {
                        Write-Log "Removed $($browser.Name) data" -Level CLEAN
                        $script:IssuesCleaned++
                    } else {
                        Write-Log "Some $($browser.Name) files locked; close browser first" -Level WARN
                        $script:IssuesRemaining++
                    }
                }
            }
        }
    }
}

function Clean-RegisteredOwner {
    if (-not (Test-ShouldProcess 'RegisteredOwner')) { return }
    Write-Log 'Registered Owner / Organization' -Level SECTION

    $ntPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    foreach ($val in @('RegisteredOwner','RegisteredOrganization')) {
        $current = (Get-ItemProperty -Path $ntPath -Name $val -ErrorAction SilentlyContinue).$val
        if ($current) {
            $script:IssuesFound++
            Write-Log "$val = '$current'" -Level FOUND
            if (-not $AuditOnly) {
                Set-ItemProperty -Path $ntPath -Name $val -Value '' -Force
                $verify = (Get-ItemProperty -Path $ntPath -Name $val -ErrorAction SilentlyContinue).$val
                if ([string]::IsNullOrEmpty($verify)) {
                    Write-Log "Cleared $val" -Level CLEAN
                    $script:IssuesCleaned++
                } else { $script:IssuesRemaining++ }
            }
        }
    }

    # OEM Info
    $oemPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'
    foreach ($val in @('Manufacturer','Model','SupportURL','SupportPhone')) {
        Remove-RegistryValueIfExists $oemPath $val "OEM Info: $val"
    }

    # Computer description
    $compDesc = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'srvcomment' -ErrorAction SilentlyContinue).srvcomment
    if ($compDesc) {
        $script:IssuesFound++
        Write-Log "Computer description: '$compDesc'" -Level FOUND
        if (-not $AuditOnly) {
            Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'srvcomment' -Value '' -Force
            Write-Log 'Cleared computer description' -Level CLEAN
            $script:IssuesCleaned++
        }
    }
}

function Clean-SetupApiLogs {
    if (-not (Test-ShouldProcess 'SetupApiLogs')) { return }
    Write-Log 'SetupAPI Logs (handled in USB section)' -Level SECTION
    Write-Log 'SetupAPI logs are truncated during USB history cleanup' -Level INFO
}

function Clean-PantherLogs {
    if (-not (Test-ShouldProcess 'PantherLogs')) { return }
    Write-Log 'Windows Panther / Install Logs' -Level SECTION

    $pantherPaths = @(
        "$env:SystemRoot\Panther",
        "$env:SystemRoot\Panther\UnattendGC",
        "$env:SystemRoot\System32\Sysprep\Panther"
    )
    foreach ($pp in $pantherPaths) {
        if (Test-Path $pp) {
            $logFiles = @(Get-ChildItem $pp -Filter '*.log' -ErrorAction SilentlyContinue) +
                        @(Get-ChildItem $pp -Filter '*.xml' -ErrorAction SilentlyContinue) +
                        @(Get-ChildItem $pp -Filter '*.txt' -ErrorAction SilentlyContinue)
            if ($logFiles.Count -gt 0) {
                $script:IssuesFound++
                Write-Log "Panther logs in $pp : $($logFiles.Count) files" -Level FOUND
                if (-not $AuditOnly) {
                    $logFiles | ForEach-Object { Set-Content -Path $_.FullName -Value '' -Force -ErrorAction SilentlyContinue }
                    Write-Log "Truncated Panther logs in $pp" -Level CLEAN
                    $script:IssuesCleaned++
                }
            }
        }
    }
}

function Clean-ErrorReports {
    if (-not (Test-ShouldProcess 'ErrorReports')) { return }
    Write-Log 'Windows Error Reporting & Crash Dumps' -Level SECTION

    $werPaths = @(
        "$env:ProgramData\Microsoft\Windows\WER",
        "$env:LocalAppData\CrashDumps"
    )
    $userProfiles = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    foreach ($p in $userProfiles) {
        $werPaths += Join-Path $p.FullName 'AppData\Local\Microsoft\Windows\WER'
        $werPaths += Join-Path $p.FullName 'AppData\Local\CrashDumps'
    }

    # System minidumps
    $werPaths += "$env:SystemRoot\Minidump"
    # Full memory dump
    if (Test-Path "$env:SystemRoot\MEMORY.DMP") {
        $script:IssuesFound++
        Write-Log "Full memory dump: $env:SystemRoot\MEMORY.DMP" -Level FOUND
        if (-not $AuditOnly) {
            Remove-Item "$env:SystemRoot\MEMORY.DMP" -Force -ErrorAction SilentlyContinue
            Write-Log 'Removed MEMORY.DMP' -Level CLEAN
            $script:IssuesCleaned++
        }
    }

    foreach ($werPath in $werPaths) {
        if (Test-Path $werPath) {
            $items = @(Get-ChildItem $werPath -Recurse -ErrorAction SilentlyContinue)
            if ($items.Count -gt 0) {
                $script:IssuesFound++
                Write-Log "WER data in $werPath : $($items.Count) items" -Level FOUND
                if (-not $AuditOnly) {
                    Remove-Item $werPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed $werPath" -Level CLEAN
                    $script:IssuesCleaned++
                }
            }
        }
    }
}

function Clean-DNSCache {
    if (-not (Test-ShouldProcess 'DNSCache')) { return }
    Write-Log 'DNS Client Cache' -Level SECTION

    $dnsEntries = @(Get-DnsClientCache -ErrorAction SilentlyContinue)
    if ($dnsEntries.Count -gt 0) {
        $script:IssuesFound++
        Write-Log "DNS cache entries: $($dnsEntries.Count)" -Level FOUND
        $dnsEntries | Select-Object -First 10 | ForEach-Object { Write-Log "  - $($_.Entry)" -Level INFO }
        if ($dnsEntries.Count -gt 10) { Write-Log "  ... and $($dnsEntries.Count - 10) more" -Level INFO }
        if (-not $AuditOnly) {
            Clear-DnsClientCache
            Write-Log 'Flushed DNS cache' -Level CLEAN
            $script:IssuesCleaned++
        }
    }
}

function Clean-ARPCache {
    if (-not (Test-ShouldProcess 'ARPCache')) { return }
    Write-Log 'ARP Cache' -Level SECTION

    $arpEntries = @(Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Permanent' })
    if ($arpEntries.Count -gt 0) {
        $script:IssuesFound++
        Write-Log "ARP cache entries: $($arpEntries.Count)" -Level FOUND
        if (-not $AuditOnly) {
            arp -d * 2>$null
            Write-Log 'Flushed ARP cache' -Level CLEAN
            $script:IssuesCleaned++
        }
    }
}

function Clean-ScheduledTasks {
    if (-not (Test-ShouldProcess 'ScheduledTasks')) { return }
    Write-Log 'Custom Scheduled Tasks' -Level SECTION

    $customTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.TaskName -notmatch '^User_Feed|^CreateExplorerShellUnelevatedTask' })
    if ($customTasks.Count -gt 0) {
        $script:IssuesFound++
        Write-Log "Custom scheduled tasks: $($customTasks.Count)" -Level FOUND
        $customTasks | ForEach-Object { Write-Log "  - $($_.TaskPath)$($_.TaskName) (Author: $($_.Author))" -Level INFO }
        if (-not $AuditOnly) {
            Write-Log 'Review tasks above manually — not auto-deleting scheduled tasks for safety' -Level WARN
            $script:IssuesRemaining++
        }
    }
}

function Clean-BITSJobs {
    if (-not (Test-ShouldProcess 'BITSJobs')) { return }
    Write-Log 'BITS Transfer Jobs' -Level SECTION

    $bitsJobs = @(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue)
    if ($bitsJobs.Count -gt 0) {
        $script:IssuesFound++
        Write-Log "BITS jobs: $($bitsJobs.Count)" -Level FOUND
        if (-not $AuditOnly) {
            $bitsJobs | Remove-BitsTransfer -ErrorAction SilentlyContinue
            Write-Log 'Removed BITS jobs' -Level CLEAN
            $script:IssuesCleaned++
        }
    }
}

function Clean-ClipboardHistory {
    if (-not (Test-ShouldProcess 'ClipboardHistory')) { return }
    Write-Log 'Clipboard History' -Level SECTION

    # Disable clipboard history
    $clipPath = 'HKCU:\Software\Microsoft\Clipboard'
    if (Test-Path $clipPath) {
        $enabled = (Get-ItemProperty $clipPath -Name 'EnableClipboardHistory' -ErrorAction SilentlyContinue).EnableClipboardHistory
        if ($enabled -eq 1) {
            $script:IssuesFound++
            Write-Log 'Clipboard history is enabled' -Level FOUND
            if (-not $AuditOnly) {
                Set-ItemProperty $clipPath -Name 'EnableClipboardHistory' -Value 0 -Force
                Write-Log 'Disabled clipboard history' -Level CLEAN
                $script:IssuesCleaned++
            }
        }
    }

    # Clear clipboard
    if (-not $AuditOnly) {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        [System.Windows.Forms.Clipboard]::Clear() 2>$null
        Write-Log 'Cleared clipboard' -Level CLEAN
    }
}

function Clean-EnvironmentVariables {
    if (-not (Test-ShouldProcess 'EnvironmentVariables')) { return }
    Write-Log 'Environment Variables (Company Pattern Scan)' -Level SECTION

    if ($CompanyPatterns.Count -eq 0) {
        Write-Log 'No company patterns specified; skipping environment variable scan' -Level INFO
        return
    }

    $envVars = [System.Environment]::GetEnvironmentVariables('Machine')
    $userEnvVars = [System.Environment]::GetEnvironmentVariables('User')

    foreach ($pattern in $CompanyPatterns) {
        foreach ($key in $envVars.Keys) {
            if ($key -match $pattern -or $envVars[$key] -match $pattern) {
                $script:IssuesFound++
                Write-Log "Machine env var matches '$pattern': $key = $($envVars[$key])" -Level FOUND
            }
        }
        foreach ($key in $userEnvVars.Keys) {
            if ($key -match $pattern -or $userEnvVars[$key] -match $pattern) {
                $script:IssuesFound++
                Write-Log "User env var matches '$pattern': $key = $($userEnvVars[$key])" -Level FOUND
            }
        }
    }
    Write-Log 'Environment variables with matches must be reviewed and cleaned manually' -Level WARN
}

function Clean-PagefileHibernation {
    if (-not (Test-ShouldProcess 'PagefileHibernation')) { return }
    Write-Log 'Pagefile & Hibernation' -Level SECTION

    # Check if pagefile clearing on shutdown is enabled
    $memMgmt = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    $clearPagefile = (Get-ItemProperty $memMgmt -Name 'ClearPageFileAtShutdown' -ErrorAction SilentlyContinue).ClearPageFileAtShutdown
    if ($clearPagefile -ne 1) {
        $script:IssuesFound++
        Write-Log 'Pagefile NOT set to clear on shutdown (may contain memory remnants)' -Level FOUND
        if (-not $AuditOnly) {
            Set-ItemProperty $memMgmt -Name 'ClearPageFileAtShutdown' -Value 1 -Type DWord -Force
            Write-Log 'Enabled pagefile clearing on shutdown' -Level CLEAN
            $script:IssuesCleaned++
        }
    }

    # Hibernation file
    if (Test-Path "$env:SystemDrive\hiberfil.sys") {
        $script:IssuesFound++
        Write-Log "Hibernation file exists: $env:SystemDrive\hiberfil.sys" -Level FOUND
        if (-not $AuditOnly) {
            powercfg /hibernate off 2>$null
            Write-Log 'Disabled hibernation (hiberfil.sys will be removed)' -Level CLEAN
            $script:IssuesCleaned++
        }
    }
}

function Search-CompanyPatterns {
    if ($CompanyPatterns.Count -eq 0) { return }
    Write-Log 'Company-Specific Pattern Scan' -Level SECTION

    $regPathsToScan = @(
        'HKLM:\SOFTWARE',
        'HKCU:\SOFTWARE'
    )

    foreach ($pattern in $CompanyPatterns) {
        Write-Log "Scanning registry for pattern: '$pattern'" -Level INFO

        foreach ($rootPath in $regPathsToScan) {
            try {
                $matches = @(Get-ChildItem $rootPath -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match $pattern } | Select-Object -First 20)
                foreach ($m in $matches) {
                    $script:IssuesFound++
                    Write-Log "Registry key matches '$pattern': $($m.Name)" -Level FOUND
                }
            } catch { }
        }
    }

    # Scan common file locations for company patterns
    Write-Log "Scanning filesystem for company patterns..." -Level INFO
    $scanPaths = @(
        "$env:SystemDrive\Users",
        "$env:ProgramData",
        "$env:SystemRoot\System32\drivers\etc\hosts"
    )

    # Check hosts file
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hostsFile) {
        $hostsContent = Get-Content $hostsFile -ErrorAction SilentlyContinue
        foreach ($pattern in $CompanyPatterns) {
            $hostsMatches = @($hostsContent | Where-Object { $_ -match $pattern })
            if ($hostsMatches.Count -gt 0) {
                $script:IssuesFound++
                Write-Log "Hosts file contains pattern '$pattern': $($hostsMatches.Count) line(s)" -Level FOUND
                $hostsMatches | ForEach-Object { Write-Log "  - $_" -Level INFO }
            }
        }
    }

    # Scan user profile folder names
    $userProfiles = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($pattern in $CompanyPatterns) {
        $profileMatches = @($userProfiles | Where-Object { $_.Name -match $pattern })
        foreach ($pm in $profileMatches) {
            $script:IssuesFound++
            Write-Log "User profile folder matches '$pattern': $($pm.FullName)" -Level FOUND
            Write-Log 'User profile folders should be removed by deleting the user account or sysprep' -Level WARN
        }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

$banner = @"

    ╔══════════════════════════════════════════════════════════════╗
    ║           PRE-DELIVERY SYSTEM CLEANUP UTILITY               ║
    ║                                                              ║
    ║   Mode: $(if ($AuditOnly) { 'AUDIT ONLY (no changes)       ' } else { 'FULL CLEANUP                  ' })║
    ╚══════════════════════════════════════════════════════════════╝

"@

Write-Host $banner -ForegroundColor Cyan
Write-Log "Script started - Mode: $(if ($AuditOnly) {'AUDIT'} else {'CLEANUP'})" -Level INFO
Write-Log "Computer: $env:COMPUTERNAME | User: $env:USERNAME" -Level INFO
if ($CompanyPatterns.Count -gt 0) {
    Write-Log "Company patterns: $($CompanyPatterns -join ', ')" -Level INFO
}
if ($SkipSections.Count -gt 0) {
    Write-Log "Skipping sections: $($SkipSections -join ', ')" -Level INFO
}

if (-not $AuditOnly) {
    Write-Host "`n  WARNING: This will permanently delete data. Press Ctrl+C to abort.`n" -ForegroundColor Red
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Run full pre-delivery cleanup')) {
        Write-Log 'Cleanup aborted by user' -Level WARN
        return
    }
}

# Run all sections
Clean-WiFiProfiles
Clean-NetworkProfiles
Clean-MappedDrives
Clean-RDP
Clean-VPN
Clean-Credentials
Clean-USBHistory
Clean-Bluetooth
Clean-Printers
Clean-RecentFiles
Clean-ExplorerMRU
Clean-JumpLists
Clean-Prefetch
Clean-ThumbnailCache
Clean-ActivityHistory
Clean-EventLogs
Clean-PowerShellHistory
Clean-TempFiles
Clean-BrowserData
Clean-RegisteredOwner
Clean-PantherLogs
Clean-ErrorReports
Clean-DNSCache
Clean-ARPCache
Clean-ScheduledTasks
Clean-BITSJobs
Clean-ClipboardHistory
Clean-EnvironmentVariables
Clean-PagefileHibernation
Search-CompanyPatterns

# ============================================================================
# SUMMARY
# ============================================================================

Write-Log 'SUMMARY' -Level SECTION

$summary = @"
  Total issues found:     $($script:IssuesFound)
  Issues cleaned:         $($script:IssuesCleaned)
  Issues remaining:       $($script:IssuesRemaining)
  Audit-only (not acted): $(if ($AuditOnly) { $script:IssuesFound } else { $script:IssuesFound - $script:IssuesCleaned - $script:IssuesRemaining })
"@
Write-Host $summary -ForegroundColor White
$script:LogEntries.Add($summary)

# Recommendations
Write-Log '' -Level INFO
Write-Log 'POST-CLEANUP RECOMMENDATIONS:' -Level SECTION
$recommendations = @(
    '1. Rename computer to customer-appropriate name: Rename-Computer -NewName "NEWNAME" -Restart',
    '2. Remove/rename your developer user profile and create customer account',
    '3. Run Disk Cleanup (cleanmgr) with all options checked',
    '4. Run cipher /w:C:\ to overwrite free space (prevents recovery of deleted files)',
    '5. Consider running sfc /scannow to verify system integrity',
    '6. If applicable, run sysprep for OOBE: C:\Windows\System32\Sysprep\sysprep.exe /oobe /generalize /shutdown',
    '7. Verify Windows activation is not tied to your organization',
    '8. Check Device Manager for any named/company-specific devices',
    '9. Review hosts file: C:\Windows\System32\drivers\etc\hosts',
    '10. Restart and re-run this script with -AuditOnly to verify cleanup'
)
$recommendations | ForEach-Object { Write-Log $_ -Level INFO }

# Save log
$script:LogEntries | Out-File -FilePath $LogPath -Encoding UTF8 -Force
Write-Host "`n  Log saved to: $LogPath`n" -ForegroundColor Green