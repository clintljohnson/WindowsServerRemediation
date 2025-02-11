function Fix-SMBSigning {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for SMB Signing on $ComputerName"

    try {
        # First verify current state
        $currentState = Check-SMBSigning -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - SMB signing is already properly configured"
            return $true
        }

        # Apply fix
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                Write-Verbose "Enabling and requiring SMB signing..."
                Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force
                return $true
            }
            catch {
                Write-Error "Failed to configure SMB signing: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully configured SMB signing" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-SMBSigning -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed - SMB signing is properly configured"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply SMB signing configuration"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 