function Fix-AutorunBehavior {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for AutorunBehavior on $ComputerName"

    try {
        # First get the current state using the check function
        $currentState = Check-AutorunBehavior -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $autorunKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                
                if (-not (Test-Path $autorunKey)) {
                    Write-Verbose "Creating Explorer policies key..."
                    New-Item -Path $autorunKey -Force | Out-Null
                }
                
                Set-ItemProperty -Path $autorunKey -Name "NoAutorun" -Value 1 -Type DWord
                return $true
            }
            catch {
                Write-Error "Failed to apply fix: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully restricted autorun behavior" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-AutorunBehavior -ComputerName $ComputerName
            
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