function Fix-ForwardSecrecyCiphers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for Forward Secrecy Ciphers on $ComputerName"

    try {
        # First verify the current state
        $currentState = Check-ForwardSecrecyCiphers -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - cipher configuration is already secure"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                # Get Windows version information
                $osInfo = Get-WmiObject -Class Win32_OperatingSystem
                $isServer2022 = $osInfo.Caption -like "*Server 2022*"
                Write-Verbose "OS Version: $($osInfo.Caption)"

                if ($isServer2022) {
                    # Server 2022 logic remains unchanged
                    # ... existing Server 2022 code ...
                } else {
                    # Pre-2022 server behavior using registry modifications
                    Write-Verbose "Pre-2022 server detected - using registry modifications"
                    
                    # Define the required cipher suites
                    $cipherSuites = @(
                        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
                    )

                    # Create the cipher suite string
                    $cipherList = $cipherSuites -join ','

                    # Set the cipher suite order
                    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
                    if (-not (Test-Path $regPath)) {
                        New-Item -Path $regPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $regPath -Name "Functions" -Value $cipherList -Type String

                    # Disable non-FS ciphers in SCHANNEL
                    $schannelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
                    $nonFSCiphers = Get-ChildItem $schannelPath -ErrorAction SilentlyContinue | 
                        Where-Object { 
                            $_.PSChildName -like "*RSA*" -and 
                            $_.PSChildName -notlike "*ECDHE*" -and 
                            $_.PSChildName -notlike "*DHE*" 
                        }

                    foreach ($cipher in $nonFSCiphers) {
                        $cipherPath = Join-Path $schannelPath $cipher.PSChildName
                        Set-ItemProperty -Path $cipherPath -Name "Enabled" -Value 0 -Type DWord
                    }

                    # Enable FS ciphers
                    foreach ($cipher in $cipherSuites) {
                        $cipherPath = Join-Path $schannelPath $cipher
                        if (-not (Test-Path $cipherPath)) {
                            New-Item -Path $cipherPath -Force | Out-Null
                        }
                        Set-ItemProperty -Path $cipherPath -Name "Enabled" -Value 1 -Type DWord
                    }
                }

                # Give the system a moment to process changes
                Start-Sleep -Seconds 2
                return $true
            }
            catch {
                Write-Error "Failed to configure cipher suites: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully configured forward secrecy ciphers" -ForegroundColor Green
            Start-Sleep -Seconds 2  # Give system time to process changes
            
            # Verify the fix
            $verifyResult = Check-ForwardSecrecyCiphers -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed: $($verifyResult.Details)"
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