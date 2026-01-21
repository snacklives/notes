# .SYNOPSIS
Detects Windows services with unquoted executable paths that contain spaces.

# .DESCRIPTION
Finds services where:
- The executable path contains spaces
- The executable portion is NOT wrapped in quotes
- (Arguments may exist and are preserved in reporting)

Outputs objects and prints a readable table.

# .NOTES
Run as admin for best visibility, though detection usually works without.

# .Code

<details>
  
```powershell
# Detects unquoted service paths in Windows Systems.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Parse-ServiceImagePath {
    param(
        [Parameter(Mandatory)]
        [string] $ImagePath
    )

    $p = $ImagePath.Trim()

    if ([string]::IsNullOrWhiteSpace($p)) {
        return $null
    }

    # Already quoted executable?
    if ($p -match '^\s*"(.*?)"\s*(.*)$') {
        return [pscustomobject]@{
            ExePath     = $matches[1]
            Args        = $matches[2].Trim()
            IsQuotedExe = $true
            Raw         = $ImagePath
        }
    }

    # Attempt to locate the executable by extension (most services use .exe)
    # Non-greedy so it stops at the first ".exe" occurrence.
    if ($p -match '^\s*(.+?\.(?:exe|com|bat|cmd))\s*(.*)$') {
        return [pscustomobject]@{
            ExePath     = $matches[1].Trim()
            Args        = $matches[2].Trim()
            IsQuotedExe = $false
            Raw         = $ImagePath
        }
    }

    # Could not parse reliably
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
    if (-not $parsed -or $parsed.PSObject.Properties.Name -contains 'ParseFailed' -and $parsed.ParseFailed) {
        return $false
    }

    # Vulnerable if EXE path contains spaces and isn't quoted
    return (($parsed.IsQuotedExe -eq $false) -and ($parsed.ExePath -match '\s'))
}

$services = Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, PathName

$findings = foreach ($s in $services) {
    if ([string]::IsNullOrWhiteSpace($s.PathName)) { continue }

    $parsed = Parse-ServiceImagePath -ImagePath $s.PathName
    $isVuln = Test-UnquotedServicePath -ImagePath $s.PathName

    if ($isVuln) {
        [pscustomobject]@{
            Name        = $s.Name
            DisplayName = $s.DisplayName
            State       = $s.State
            StartMode   = $s.StartMode
            RawPath     = $s.PathName
            ExePath     = $parsed.ExePath
            Args        = $parsed.Args
        }
    }
}

if (-not $findings -or $findings.Count -eq 0) {
    Write-Host "No unquoted service paths detected." -ForegroundColor Green
    return
}

Write-Host ("Detected {0} service(s) with unquoted executable paths:" -f $findings.Count) -ForegroundColor Yellow
$findings |
    Sort-Object StartMode, Name |
    Format-Table -AutoSize Name, StartMode, State, ExePath, Args

# Also return objects for pipeline/exports
$findings
```
</details>
