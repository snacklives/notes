# Windows Server Unquoted Service Path Enumeration Fix
## SYNOPSIS
Quotes unquoted Windows service executable paths (with spaces) while preserving arguments.

## DESCRIPTION
For each service with an unquoted executable path containing spaces:
- Parses the ImagePath (Win32_Service.PathName)
- Rewrites only the executable portion to be quoted: "C:\Path With Spaces\app.exe" <args>
- Writes to HKLM:\SYSTEM\CurrentControlSet\Services\<ServiceName>\ImagePath

## Safety features:
- Supports -WhatIf and -Confirm
- Backs up each ImagePath to a .reg export (one per service) before modification

## IMPORTANT:
- Requires running PowerShell as Administrator.
- Does NOT restart services. Restart manually if needed.

### PARAMETERs 
| Parameter | Description |
| ------------- | ------------- |
|BackupDir|Directory to store .reg backups.|

### SCRIPT
```powershell
.\Fix-UnquotedServicePaths.ps1 -WhatIf
```
```powershell
.\Fix-UnquotedServicePaths.ps1 -BackupDir "C:\Temp\ServiceBackups"
```

### CODE
<details>

  ```powershell
# Quotes unquoted Windows service executable paths (with spaces) while preserving arguments.

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
param(
    [string] $BackupDir = (Join-Path $env:TEMP ("ServiceImagePathBackups_{0:yyyyMMdd_HHmmss}" -f (Get-Date)))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Parse-ServiceImagePath {
    param(
        [Parameter(Mandatory)]
        [string] $ImagePath
    )

    $p = $ImagePath.Trim()
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }

    if ($p -match '^\s*"(.*?)"\s*(.*)$') {
        return [pscustomobject]@{
            ExePath     = $matches[1]
            Args        = $matches[2].Trim()
            IsQuotedExe = $true
            Raw         = $ImagePath
        }
    }

    if ($p -match '^\s*(.+?\.(?:exe|com|bat|cmd))\s*(.*)$') {
        return [pscustomobject]@{
            ExePath     = $matches[1].Trim()
            Args        = $matches[2].Trim()
            IsQuotedExe = $false
            Raw         = $ImagePath
        }
    }

    return [pscustomobject]@{
        ExePath     = $null
        Args        = $null
        IsQuotedExe = $false
        Raw         = $ImagePath
        ParseFailed = $true
    }
}

function Test-UnquotedServicePath {
    param(
        [Parameter(Mandatory)]
        [string] $ImagePath
    )

    $parsed = Parse-ServiceImagePath -ImagePath $ImagePath
    if (-not $parsed -or ($parsed.PSObject.Properties.Name -contains 'ParseFailed' -and $parsed.ParseFailed)) {
        return $false
    }

    return (($parsed.IsQuotedExe -eq $false) -and ($parsed.ExePath -match '\s'))
}

function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator."
    }
}

function Export-ServiceImagePathBackup {
    param(
        [Parameter(Mandatory)] [string] $ServiceName,
        [Parameter(Mandatory)] [string] $DestinationFolder
    )

    New-Item -ItemType Directory -Path $DestinationFolder -Force | Out-Null

    $regKey = "HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $safeName = ($ServiceName -replace '[^\w\.-]', '_')
    $outFile = Join-Path $DestinationFolder ("{0}.reg" -f $safeName)

    # Use reg.exe to export (most compatible)
    & reg.exe export $regKey $outFile /y | Out-Null

    return $outFile
}

Ensure-Admin

$services = Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, PathName

$targets = foreach ($s in $services) {
    if ([string]::IsNullOrWhiteSpace($s.PathName)) { continue }
    if (Test-UnquotedServicePath -ImagePath $s.PathName) {
        $parsed = Parse-ServiceImagePath -ImagePath $s.PathName

        $newImagePath = '"' + $parsed.ExePath + '"'
        if (-not [string]::IsNullOrWhiteSpace($parsed.Args)) {
            $newImagePath += " " + $parsed.Args
        }

        [pscustomobject]@{
            Name        = $s.Name
            DisplayName = $s.DisplayName
            State       = $s.State
            StartMode   = $s.StartMode
            OldImagePath= $s.PathName
            ExePath     = $parsed.ExePath
            Args        = $parsed.Args
            NewImagePath= $newImagePath
        }
    }
}

if (-not $targets -or $targets.Count -eq 0) {
    Write-Host "No unquoted service paths found to fix." -ForegroundColor Green
    return
}

Write-Host ("Found {0} service(s) to update." -f $targets.Count) -ForegroundColor Yellow
$targets | Sort-Object StartMode, Name | Format-Table -AutoSize Name, StartMode, State, ExePath, Args

foreach ($t in $targets) {
    $svcKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($t.Name)"
    $propName   = "ImagePath"

    if ($PSCmdlet.ShouldProcess($t.Name, "Set $propName to: $($t.NewImagePath)")) {
        $backupFile = Export-ServiceImagePathBackup -ServiceName $t.Name -DestinationFolder $BackupDir

        try {
            # Write as expandable string when it contains environment variables, otherwise normal string.
            # Keep it simple: always use ExpandString to preserve any %SystemRoot% etc.
            Set-ItemProperty -Path $svcKeyPath -Name $propName -Value $t.NewImagePath -Type ExpandString

            Write-Host ("[OK] {0} updated. Backup: {1}" -f $t.Name, $backupFile) -ForegroundColor Green
        }
        catch {
            Write-Host ("[FAIL] {0}: {1}" -f $t.Name, $_.Exception.Message) -ForegroundColor Red
            Write-Host ("       Backup file: {0}" -f $backupFile) -ForegroundColor DarkYellow
        }
    }
}

Write-Host ""
Write-Host "Done. Backups stored in:" -ForegroundColor Cyan
Write-Host $BackupDir -ForegroundColor Cyan
Write-Host ""
Write-Host "Note: Services were NOT restarted. Restart affected services (or reboot) if required." -ForegroundColor Yellow

```
</details>
