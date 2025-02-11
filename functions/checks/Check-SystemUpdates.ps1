function Check-SystemUpdates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 1
        Name = "System Updates Status"
        Status = "OK"
        Details = "System updates are current"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # Get Windows Update information
            $hotFixes = Get-CimInstance -ClassName Win32_QuickFixEngineering |
                Sort-Object InstalledOn -Descending
            
            # Get OS information
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            
            @{
                LastUpdate = if ($hotFixes) { $hotFixes[0].InstalledOn } else { $null }
                OSDetails = "$($os.Caption) - Build $($os.BuildNumber)"
            }
        }

        if ($checkResult.LastUpdate) {
            $lastUpdateFormatted = $checkResult.LastUpdate.ToString('MM/dd/yyyy')
            $DaysSinceLastUpdate = (Get-Date) - $checkResult.LastUpdate
            
            if ($DaysSinceLastUpdate.Days -gt 30) {
                $result.Status = "WARNING"
                $result.Details = "No updates installed in the last $($DaysSinceLastUpdate.Days) days. Last update: $lastUpdateFormatted. OS: $($checkResult.OSDetails)"
            }
            else {
                $result.Details = "System updates are current. Last update: $lastUpdateFormatted. OS: $($checkResult.OSDetails)"
            }
        }
        else {
            $result.Status = "WARNING"
            $result.Details = "No update history found on $ComputerName"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking updates on $ComputerName`: $_"
    }

    return $result
} 