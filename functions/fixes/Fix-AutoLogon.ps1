function Fix-AutoLogon {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    Write-Verbose "Starting fix operation for AutoLogon on $ComputerName"
    
    try {
        # First get the current state using the check function
        $currentState = & "Check-AutoLogon" -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        Write-Verbose "The following registry settings will be modified:"
        Write-Verbose "- HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon"
        Write-Verbose "- HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword (will be removed)"

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $winlogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
                
                # Disable AutoAdminLogon
                Set-ItemProperty -Path $winlogonKey -Name "AutoAdminLogon" -Value "0" -Type String
                
                # Remove any stored credentials
                Remove-ItemProperty -Path $winlogonKey -Name "DefaultPassword" -ErrorAction SilentlyContinue
                return $true
            }
            catch {
                Write-Error "Failed to apply fix: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully disabled automatic logon" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = & "Check-AutoLogon" -ComputerName $ComputerName
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply fix"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 