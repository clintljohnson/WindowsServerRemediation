function Check-InstallerPrivileges {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Checking Windows Installer elevated privileges setting on $ComputerName..."
    
    $result = @{
        CheckNumber = 12
        Name = "Windows Installer Elevated Privileges"
        Status = "OK"
        Details = "Windows Installer is not configured to always install with elevated privileges"
        Function = $MyInvocation.MyCommand.Name
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "Checking installer privileges registry settings"
            
            $settings = @{
                HKLM = $null
                HKCU = $null
            }
            
            # Check HKLM
            $hklmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
            if (Test-Path $hklmPath) {
                $settings.HKLM = (Get-ItemProperty -Path $hklmPath -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
            }
            
            # Check HKCU
            $hkcuPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
            if (Test-Path $hkcuPath) {
                $settings.HKCU = (Get-ItemProperty -Path $hkcuPath -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
            }
            
            return $settings
        }

        $issues = @()
        if ($null -ne $checkResult.HKLM -and $checkResult.HKLM -eq 1) {
            $issues += "HKLM: AlwaysInstallElevated is enabled"
        }
        if ($null -ne $checkResult.HKCU -and $checkResult.HKCU -eq 1) {
            $issues += "HKCU: AlwaysInstallElevated is enabled"
        }

        if ($issues.Count -gt 0) {
            Write-Verbose "Found elevated installer privileges issues on $ComputerName"
            $result.Status = "WARNING"
            $result.Details = $issues -join "; "
        }
    }
    catch {
        Write-Verbose "Error checking installer privileges: $_"
        $result.Status = "WARNING"
        $result.Details = "Failed to check Windows Installer privileges: $_"
    }

    return $result
} 