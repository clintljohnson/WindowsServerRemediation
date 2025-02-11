function Check-RemoteRegistry {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 3
        Name = "Remote Registry Paths"
        Status = "OK"
        Details = "Remote registry paths are properly configured"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # Check Remote Registry service
            $service = Get-Service -Name "RemoteRegistry" -ErrorAction Stop
            
            $paths = @(
                "SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg",
                "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Remote Registry"
            )
            
            $issues = @()
            
            # Check service status
            if ($service.Status -eq 'Running') {
                $issues += "Remote Registry service is running"
            }
            
            # Check registry paths
            foreach ($path in $paths) {
                try {
                    $regKey = Get-ItemProperty -Path "HKLM:\$path" -ErrorAction Stop
                    $issues += "Unauthorized registry path exists: $path"
                }
                catch [System.Management.Automation.ItemNotFoundException] {
                    # This is good - path doesn't exist
                }
            }
            
            return $issues
        }

        if ($checkResult.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = $checkResult -join '; '
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking remote registry paths: $_"
    }

    return $result
} 