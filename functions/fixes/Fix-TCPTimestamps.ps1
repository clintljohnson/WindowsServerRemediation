function Fix-TCPTimestamps {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting TCP timestamp remediation on $ComputerName"

    try {
        # First verify current state
        $currentState = Check-TCPTimestamps -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - TCP timestamps are already properly configured"
            return $true
        }

        # Apply the fix
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                # Set Tcp1323Opts to 1 to enable window scaling but disable timestamps
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" `
                    -Name "Tcp1323Opts" -Value 1 -Type DWord -Force
                
                Write-Verbose "TCP timestamp configuration updated"
                return $true
            }
            catch {
                Write-Error "Failed to update TCP timestamp configuration: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully disabled TCP timestamps" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-TCPTimestamps -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed - TCP timestamps are now disabled"
                Write-Warning "Note: A system restart may be required for changes to take effect"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply TCP timestamp fix"
        return $false
    }
    catch {
        Write-Error "Error in TCP timestamp remediation: $_"
        return $false
    }
} 