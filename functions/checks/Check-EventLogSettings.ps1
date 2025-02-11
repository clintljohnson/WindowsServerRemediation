function Check-EventLogSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 24
        Name = "Event Log Settings"
        Status = "OK"
        Details = "Event log settings are properly configured"
    }

    try {
        Write-Verbose "Checking event log settings on $ComputerName"

        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $logs = @(
                @{ Name = 'Security'; MinSize = 1024 },  # 1GB
                @{ Name = 'Application'; MinSize = 100 }, # 100MB
                @{ Name = 'System'; MinSize = 100 }      # 100MB
            )
            $issues = @()
            $compliant = @()
            
            foreach ($log in $logs) {
                $eventLog = Get-WinEvent -ListLog $log.Name -ErrorAction Stop
                
                # Check log size
                $sizeInMB = $eventLog.MaximumSizeInBytes / 1MB
                if ($sizeInMB -lt $log.MinSize) {
                    $issues += "$($log.Name) log size ($sizeInMB MB) is below recommended $($log.MinSize)MB"
                } else {
                    $compliant += "$($log.Name) log properly set to minimum $($log.MinSize)MB"
                }
                
                # Check retention
                if (-not $eventLog.IsEnabled) {
                    $issues += "$($log.Name) log is disabled"
                }
                if ($eventLog.IsLogFull) {
                    $issues += "$($log.Name) log is full"
                }
            }
            
            return @{
                Issues = $issues
                Compliant = $compliant
            }
        }

        if ($checkResult.Issues.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = ($checkResult.Compliant + $checkResult.Issues) -join "; "
        } else {
            $result.Details = $checkResult.Compliant -join "; "
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking event log settings on $ComputerName`: $_"
    }

    return $result
} 