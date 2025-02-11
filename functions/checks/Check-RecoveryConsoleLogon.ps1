function Check-RecoveryConsoleLogon {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        [Parameter(Mandatory=$false)]
        [System.Collections.Hashtable]$Parameters
    )

    Write-Verbose "Checking Recovery Console automatic logon settings on $ComputerName..."
    
    $result = @{
        CheckNumber = 8
        Category = "Security"
        Name = "Recovery Console Automatic Logon"
        Status = "OK"
        Details = "Recovery Console automatic logon is properly disabled"
        Function = $MyInvocation.MyCommand.Name
        Reference = "MS Security Baseline"
        Resolution = "Configure 'SecurityLevel' to 0 in HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "Checking Recovery Console registry settings"
            
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
            $setting = Get-ItemProperty -Path $regPath -Name "SecurityLevel" -ErrorAction SilentlyContinue
            
            return @{
                Exists = ($null -ne $setting)
                Value = if ($null -ne $setting) { $setting.SecurityLevel } else { $null }
            }
        }

        if ($null -eq $checkResult.Value) {
            Write-Verbose "Recovery Console SecurityLevel setting not found on $ComputerName"
            $result.Status = "WARNING"
            $result.Details = "Recovery Console automatic logon setting not configured"
            $result.Resolution = "Configure the Recovery Console SecurityLevel setting in the registry"
        }
        elseif ($checkResult.Value -ne 0) {
            Write-Verbose "Recovery Console automatic logon is enabled on $ComputerName"
            $result.Status = "WARNING"
            $result.Details = "Recovery Console automatic logon is enabled (SecurityLevel = $($checkResult.Value))"
            $result.Resolution = "Set SecurityLevel to 0 to disable Recovery Console automatic logon"
        }
        else {
            Write-Verbose "Recovery Console automatic logon is properly disabled on $ComputerName"
        }
    }
    catch {
        Write-Verbose "Error checking Recovery Console settings: $_"
        $result.Status = "WARNING"
        $result.Details = "Error checking Recovery Console settings: $_"
    }

    return $result
} 