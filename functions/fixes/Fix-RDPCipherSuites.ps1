function Fix-RDPCipherSuites {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting comprehensive cipher suite fix for $ComputerName"

    try {
        # First verify current state
        $currentState = Check-RDPCipherSuites -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current cipher configuration is compliant"
            return $true
        }

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                Write-Verbose "Starting remediation on $using:ComputerName"

                # Get Windows Server version
                $osVersion = Get-WmiObject -Class Win32_OperatingSystem
                $isServer2019 = $osVersion.Caption -like "*2019*"
                Write-Verbose "Detected OS: $($osVersion.Caption)"

                # Disable weak ciphers
                Write-Verbose "Disabling weak ciphers..."
                $weakCiphers = @(
                    'DES 56/56',
                    'NULL',
                    'RC2 40/128',
                    'RC2 56/128',
                    'RC2 128/128',
                    'RC4 40/128',
                    'RC4 56/128',
                    'RC4 64/128',
                    'RC4 128/128'
                )
                
                foreach ($cipher in $weakCiphers) {
                    Write-Verbose "Processing cipher: $cipher"
                    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
                    if (-not (Test-Path $path)) {
                        Write-Verbose "Creating path: $path"
                        New-Item -Path $path -Force | Out-Null
                    }
                    Write-Verbose "Disabling cipher: $cipher"
                    Set-ItemProperty -Path $path -Name "Enabled" -Value 0 -Type DWORD
                }

                # Configure TLS protocols
                Write-Verbose "Configuring TLS protocols..."
                # Disable TLS 1.0 and 1.1 for all supported server versions
                $protocols = @('TLS 1.0', 'TLS 1.1')
                
                foreach ($protocol in $protocols) {
                    Write-Verbose "Disabling $protocol"
                    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
                    if (-not (Test-Path $path)) {
                        Write-Verbose "Creating path: $path"
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "Enabled" -Value 0 -Type DWORD
                    Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value 1 -Type DWORD
                }
                
                # Enable TLS 1.2
                Write-Verbose "Enabling TLS 1.2"
                $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
                if (-not (Test-Path $path)) {
                    Write-Verbose "Creating path: $path"
                    New-Item -Path $path -Force | Out-Null
                }
                Set-ItemProperty -Path $path -Name "Enabled" -Value 1 -Type DWORD
                Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value 0 -Type DWORD

                # Set cipher suites based on OS version
                Write-Verbose "Configuring cipher suites..."
                if ($isServer2019) {
                    $cipherSuites = @(
                        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                        'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                        'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
                    )
                } else {
                    $cipherSuites = @(
                        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA384',
                        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
                        'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
                    )
                }
                
                $registryPaths = @(
                    'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002',
                    'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002'
                )
                
                foreach ($path in $registryPaths) {
                    Write-Verbose "Setting cipher order in: $path"
                    if (-not (Test-Path $path)) {
                        Write-Verbose "Creating path: $path"
                        New-Item -Path $path -Force | Out-Null
                    }
                    
                    # Remove existing Functions value if it exists
                    Remove-ItemProperty -Path $path -Name "Functions" -ErrorAction SilentlyContinue
                    
                    # Set new Functions value as REG_MULTI_SZ
                    $null = New-ItemProperty -Path $path -Name "Functions" -Value $cipherSuites -PropertyType MultiString -Force
                }

                # Force Group Policy update
                Write-Verbose "Updating Group Policy..."
                Start-Process gpupdate.exe -ArgumentList "/force" -Wait -NoNewWindow
                Write-Verbose "Group Policy update completed"

                # Restart required services
                $services = @(
                    'CryptoSvc',
                    'UmRdpService',
                    'SessionEnv',
                    'TermService'
                )
                
                # Stop services in reverse order
                Write-Verbose "Stopping services..."
                for ($i = $services.Count - 1; $i -ge 0; $i--) {
                    $service = $services[$i]
                    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                        Write-Verbose "Stopping $service..."
                        Stop-Service -Name $service -Force -ErrorAction Stop
                        Start-Sleep -Seconds 2
                    }
                }

                # Start services in correct order
                Write-Verbose "Starting services..."
                foreach ($service in $services) {
                    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                        Write-Verbose "Starting $service..."
                        Start-Service -Name $service -ErrorAction Stop
                        Start-Sleep -Seconds 2
                    }
                }
                Write-Verbose "All services have been restarted"

                return $true
            }
            catch {
                Write-Error "Failed to apply cipher suite policy settings: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully applied secure cipher suite configuration" -ForegroundColor Green
            
            # Verify the fix
            Write-Verbose "Verifying configuration..."
            $verifyResult = Check-RDPCipherSuites -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply cipher suite configuration"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
}