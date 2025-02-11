function Fix-RemoteAssistance {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for Remote Assistance on $ComputerName"

    try {
        # First check current state
        $currentState = Check-RemoteAssistance -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - Remote Assistance is already properly configured"
            return $true
        }

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                Write-Verbose "Disabling Remote Assistance registry setting"
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
                
                Write-Verbose "Stopping Remote Access service if running"
                Stop-Service -Name "RemoteAccess" -Force -ErrorAction SilentlyContinue
                
                Write-Verbose "Disabling Remote Access service"
                Set-Service -Name "RemoteAccess" -StartupType Disabled -ErrorAction SilentlyContinue
                
                Write-Verbose "Disabling Remote Assistance firewall rules"
                Get-NetFirewallRule -DisplayGroup "Remote Assistance" | Set-NetFirewallRule -Enabled False -ErrorAction SilentlyContinue
                
                return $true
            }
            catch {
                Write-Error "Failed to apply fix: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully applied Remote Assistance fixes" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-RemoteAssistance -ComputerName $ComputerName
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply Remote Assistance fixes"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 