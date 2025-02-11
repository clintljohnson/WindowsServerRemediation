function Fix-StaticKeyCiphers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for static key cipher suites on $ComputerName"

    try {
        # First check current state
        $currentState = Check-StaticKeyCiphers -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - static key cipher suites are already disabled"
            return $true
        }

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                # Get current cipher suite order
                $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
                $currentOrder = (Get-ItemProperty -Path $regPath -Name 'Functions' -ErrorAction SilentlyContinue).Functions

                if ($currentOrder) {
                    # Remove all TLS_RSA static cipher suites
                    $newOrder = ($currentOrder -split ',' | Where-Object { $_ -notlike "*TLS_RSA_*" }) -join ','
                    
                    # Set new cipher suite order
                    Set-ItemProperty -Path $regPath -Name 'Functions' -Value $newOrder
                    Write-Verbose "Updated cipher suite order to remove static key ciphers"
                    
                    # Force update of security settings
                    $null = gpupdate /force
                    
                    return $true
                }
                return $false
            }
            catch {
                Write-Error "Failed to disable static key cipher suites: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully disabled static key cipher suites" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-StaticKeyCiphers -ComputerName $ComputerName
            
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