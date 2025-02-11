function Fix-WeakCiphers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for weak cipher suites on $ComputerName"

    try {
        # First verify the current state
        $currentState = Check-WeakCiphers -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - cipher configuration is already compliant"
            return $true
        }

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                Write-Verbose "Starting cipher suite remediation"
                
                # First, disable weak TLS cipher suites
                Write-Verbose "Disabling weak TLS cipher suites..."
                $weakPatterns = @(
                    'NULL',
                    'RC4',
                    'RC2',
                    'DES',
                    '3DES',
                    'MD5',
                    'PSK',
                    'SHA1'
                )

                # Get current cipher suites
                $currentCiphers = Get-TlsCipherSuite
                
                foreach ($cipher in $currentCiphers) {
                    $cipherName = if ($cipher.Name) { $cipher.Name } else { $cipher.ToString() }
                    
                    # Check if this is a weak cipher
                    $isWeak = $false
                    foreach ($pattern in $weakPatterns) {
                        if ($cipherName -match $pattern) {
                            $isWeak = $true
                            break
                        }
                    }
                    
                    if ($isWeak) {
                        Write-Verbose "Disabling weak cipher suite: $cipherName"
                        try {
                            Disable-TlsCipherSuite -Name $cipherName -ErrorAction Stop
                            Write-Verbose "Successfully disabled: $cipherName"
                        }
                        catch {
                            Write-Warning "Failed to disable cipher suite $cipherName : $_"
                        }
                    }
                }

                # Now configure the registry settings
                $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
                
                # Define weak ciphers to disable in registry
                $weakCiphers = @(
                    'NULL',
                    'DES 56/56',
                    'RC2 40/128',
                    'RC2 56/128',
                    'RC2 128/128',
                    'RC4 40/128',
                    'RC4 56/128',
                    'RC4 64/128',
                    'RC4 128/128',
                    'Triple DES 168'
                )

                # Ensure base path exists
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }

                # Disable weak ciphers in registry
                foreach ($cipher in $weakCiphers) {
                    $cipherPath = Join-Path $regPath $cipher
                    if (-not (Test-Path $cipherPath)) {
                        New-Item -Path $cipherPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $cipherPath -Name 'Enabled' -Value 0 -Type DWord
                    Write-Verbose "Disabled cipher in registry: $cipher"
                }

                # Enable strong cipher suites
                $strongCiphers = @(
                    'TLS_AES_256_GCM_SHA384',
                    'TLS_AES_128_GCM_SHA256',
                    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
                )

                foreach ($cipher in $strongCiphers) {
                    Write-Verbose "Enabling strong cipher suite: $cipher"
                    try {
                        Enable-TlsCipherSuite -Name $cipher -ErrorAction Stop
                        Write-Verbose "Successfully enabled: $cipher"
                    }
                    catch {
                        Write-Warning "Failed to enable cipher suite $cipher : $_"
                    }
                }

                # Configure protocol defaults
                $protocols = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2')
                $protocolPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

                foreach ($protocol in $protocols) {
                    $basePath = Join-Path $protocolPath $protocol
                    $serverPath = Join-Path $basePath 'Server'
                    $clientPath = Join-Path $basePath 'Client'

                    foreach ($path in @($basePath, $serverPath, $clientPath)) {
                        if (-not (Test-Path $path)) {
                            New-Item -Path $path -Force | Out-Null
                        }
                    }

                    if ($protocol -eq 'TLS 1.2') {
                        Set-ItemProperty -Path $serverPath -Name 'Enabled' -Value 1 -Type DWord
                        Set-ItemProperty -Path $serverPath -Name 'DisabledByDefault' -Value 0 -Type DWord
                        Set-ItemProperty -Path $clientPath -Name 'Enabled' -Value 1 -Type DWord
                        Set-ItemProperty -Path $clientPath -Name 'DisabledByDefault' -Value 0 -Type DWord
                    }
                    else {
                        Set-ItemProperty -Path $serverPath -Name 'Enabled' -Value 0 -Type DWord
                        Set-ItemProperty -Path $serverPath -Name 'DisabledByDefault' -Value 1 -Type DWord
                        Set-ItemProperty -Path $clientPath -Name 'Enabled' -Value 0 -Type DWord
                        Set-ItemProperty -Path $clientPath -Name 'DisabledByDefault' -Value 1 -Type DWord
                    }
                }

                Write-Verbose "Cipher suite remediation completed"
                return $true
            }
            catch {
                Write-Error "Failed to apply cipher suite changes: $_"
                return $false
            }
        } -Verbose

        if ($result) {
            Write-Host "Successfully updated cipher suite configuration" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-WeakCiphers -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply cipher suite changes"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 