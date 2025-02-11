function Fix-RecoveryConsoleLogon {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for Recovery Console Logon on $ComputerName"

    try {
        # First check current state
        $currentState = Check-RecoveryConsoleLogon -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - Recovery Console settings are compliant"
            return $true
        }

        Write-Verbose "Current issues: $($currentState.Details)"

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                Write-Verbose "Setting Recovery Console SecurityLevel to 0"
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
                
                # Ensure registry path exists
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                
                Set-ItemProperty -Path $regPath -Name "SecurityLevel" -Value 0 -Type DWord
                return $true
            }
            catch {
                Write-Error "Failed to set Recovery Console settings: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully disabled Recovery Console automatic logon" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-RecoveryConsoleLogon -ComputerName $ComputerName
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            Write-Warning "Fix applied but verification failed: $($verifyResult.Details)"
            return $false
        }

        Write-Warning "Failed to apply Recovery Console settings"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 