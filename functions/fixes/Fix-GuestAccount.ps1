function Fix-GuestAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for Guest Account on $ComputerName"

    try {
        # Check current state
        $currentState = Check-GuestAccount -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - Guest account already disabled"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction Stop
                if ($guestAccount.Enabled) {
                    Disable-LocalUser -Name "Guest" -ErrorAction Stop
                }
                return $true
            }
            catch {
                Write-Error "Failed to disable Guest account: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully disabled Guest account" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-GuestAccount -ComputerName $ComputerName
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
        }
        
        Write-Warning "Failed to disable Guest account or verification failed"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 