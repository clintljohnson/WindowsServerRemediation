function Check-UnnecessaryServices {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 23
        Name = "Unnecessary Services"
        Status = "OK"
        Details = "No unnecessary services found running"
    }

    try {
        Write-Verbose "Checking unnecessary services on $ComputerName"

        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # List of potentially unnecessary services
            $unnecessaryServices = @(
                @{Name = "SNMP"; DisplayName = "Simple Network Management Protocol"},
                @{Name = "TlntSvr"; DisplayName = "Telnet"},
                @{Name = "FTPSVC"; DisplayName = "FTP Server"},
                @{Name = "SharedAccess"; DisplayName = "Internet Connection Sharing"},
                @{Name = "simptcp"; DisplayName = "Simple TCP/IP Services"},
                @{Name = "Browser"; DisplayName = "Computer Browser"},
                @{Name = "RemoteRegistry"; DisplayName = "Remote Registry"}
            )

            # Get running services
            $runningServices = Get-Service | 
                Where-Object { $_.Status -eq 'Running' } |
                Select-Object Name, DisplayName

            # Find matches
            $foundServices = $unnecessaryServices | 
                Where-Object { $runningServices.Name -contains $_.Name } |
                Select-Object DisplayName

            return $foundServices
        }

        if ($checkResult.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = "Found unnecessary services running: $($checkResult.DisplayName -join ', ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking unnecessary services on $ComputerName`: $_"
    }

    return $result
} 