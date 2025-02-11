function Fix-3DESCiphers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for 3DES Ciphers on $ComputerName"

    try {
        # First verify current state
        $currentState = Check-3DESCiphers -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - 3DES ciphers are already disabled"
            return $true
        }

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                # Create and disable 3DES cipher registry keys
                $paths = @(
                    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168",
                    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168"
                )

                foreach ($path in $paths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "Enabled" -Value 0 -Type DWord
                }

                # Update SSL cipher suite order to remove 3DES
                $sslPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
                if (Test-Path $sslPath) {
                    $currentOrder = (Get-ItemProperty -Path $sslPath -ErrorAction SilentlyContinue).'Functions'
                    if ($currentOrder) {
                        $newOrder = $currentOrder -split ',' | Where-Object { $_ -notmatch 'TLS_RSA_WITH_3DES' } | Join-String -Separator ','
                        Set-ItemProperty -Path $sslPath -Name 'Functions' -Value $newOrder
                    }
                }

                return $true
            }
            catch {
                Write-Error "Failed to disable 3DES ciphers: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully disabled 3DES cipher suites" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-3DESCiphers -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed - 3DES ciphers are now disabled"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply 3DES cipher fixes"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 