function Fix-WinVerifyTrust {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for WinVerifyTrust on $ComputerName"

    try {
        # First verify current state
        $currentState = Check-WinVerifyTrust -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - WinVerifyTrust is already properly configured"
            return $true
        }

        # Apply the fix
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $paths = @(
                    "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config",
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
                )
                
                foreach ($registryPath in $paths) {
                    # Create the registry key if it doesn't exist
                    if (-not (Test-Path $registryPath)) {
                        Write-Verbose "Creating registry key: $registryPath"
                        New-Item -Path $registryPath -Force | Out-Null
                    }

                    # Set the registry value as REG_SZ instead of REG_DWORD
                    Write-Verbose "Setting EnableCertPaddingCheck to '1' in $registryPath"
                    Set-ItemProperty -Path $registryPath -Name "EnableCertPaddingCheck" -Value "1" -Type String
                }
                
                return $true
            }
            catch {
                Write-Error "Failed to apply WinVerifyTrust fix: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully applied WinVerifyTrust fix" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-WinVerifyTrust -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "WinVerifyTrust fix verification passed"
                return $true
            }
            else {
                Write-Warning "WinVerifyTrust fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply WinVerifyTrust fix"
        return $false
    }
    catch {
        Write-Error "Error in WinVerifyTrust fix operation: $_"
        return $false
    }
} 