function Fix-AutoplayStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for AutoplayStatus on $ComputerName"

    try {
        # First get the current state using the check function
        $currentState = Check-AutoplayStatus -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $autoplayKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                
                # Create the key if it doesn't exist
                if (-not (Test-Path $autoplayKey)) {
                    Write-Verbose "Creating Explorer policies key..."
                    New-Item -Path $autoplayKey -Force | Out-Null
                }
                
                # Set the value to disable autoplay for all drives
                Set-ItemProperty -Path $autoplayKey -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
                return $true
            }
            catch {
                Write-Error "Failed to apply fix: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully disabled Autoplay for all drives" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-AutoplayStatus -ComputerName $ComputerName
            
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