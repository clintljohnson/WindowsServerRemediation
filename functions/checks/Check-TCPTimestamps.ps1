function Check-TCPTimestamps {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 31
        Name = "TCP Timestamp Responses"
        Status = "OK"
        Details = "TCP timestamps are properly disabled"
    }

    try {
        Write-Verbose "Checking TCP timestamp configuration on $ComputerName"
        
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $tcpParams = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue
            return @{
                Tcp1323Opts = $tcpParams.Tcp1323Opts
                Exists = $null -ne $tcpParams.Tcp1323Opts
            }
        }

        if (-not $checkResult.Exists) {
            $result.Status = "WARNING"
            $result.Details = "TCP timestamp configuration is not set (defaults to enabled)"
            return $result
        }

        # Values:
        # 0 = Disabled (both timestamps and window scaling)
        # 1 = Window scaling enabled only (timestamps disabled)
        # 2 = Timestamps enabled only (not recommended)
        # 3 = Both enabled (not recommended)
        if ($checkResult.Tcp1323Opts -in @(2,3)) {
            $result.Status = "WARNING"
            $result.Details = "TCP timestamps are enabled (current value: $($checkResult.Tcp1323Opts))"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking TCP timestamp configuration: $_"
    }

    return $result
} 