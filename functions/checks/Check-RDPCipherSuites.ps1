function Check-RDPCipherSuites {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 43
        Name = "RDP Cipher Suite Configuration"
        Status = "OK"
        Details = "RDP cipher suites are configured correctly"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $issues = @()
            
            # Detect OS version
            $osVersion = Get-WmiObject -Class Win32_OperatingSystem
            $isServer2019 = $osVersion.Caption -like "*2019*"
            Write-Verbose "Detected OS: $($osVersion.Caption)"
            
            # Define required cipher suites based on OS version
            if ($isServer2019) {
                $requiredCipherSuites = @(
                    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                    'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                    'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
                )
            } else {
                $requiredCipherSuites = @(
                    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA384',
                    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                    'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
                    'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
                )
            }

            # Check SSL Cipher Suite Order policy in both locations
            Write-Verbose "Checking SSL Cipher Suite Order policies..."
            $policyPaths = @(
                "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002",
                "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
            )

            foreach ($policyPath in $policyPaths) {
                Write-Verbose "Checking path: $policyPath"
                
                if (-not (Test-Path $policyPath)) {
                    $issues += "SSL Cipher Suite Order policy is not configured at $policyPath"
                    continue
                }

                $currentPolicy = Get-ItemProperty -Path $policyPath -Name "Functions" -ErrorAction SilentlyContinue
                
                if (-not $currentPolicy) {
                    $issues += "Functions key not found in $policyPath"
                    continue
                }

                # Handle both REG_SZ and REG_MULTI_SZ cases
                $currentCiphers = if ($currentPolicy.Functions -is [string]) {
                    $currentPolicy.Functions -split ','
                } else {
                    $currentPolicy.Functions
                }

                Write-Verbose "Current SSL cipher policy at $policyPath`: $($currentCiphers -join ', ')"
                
                # Compare arrays regardless of order
                $missingCiphers = $requiredCipherSuites | Where-Object { $_ -notin $currentCiphers }
                $extraCiphers = $currentCiphers | Where-Object { $_ -notin $requiredCipherSuites }

                if ($missingCiphers -or $extraCiphers) {
                    $issues += "Incorrect cipher configuration in $policyPath"
                    if ($missingCiphers) {
                        Write-Verbose "Missing ciphers: $($missingCiphers -join ', ')"
                    }
                    if ($extraCiphers) {
                        Write-Verbose "Extra ciphers: $($extraCiphers -join ', ')"
                    }
                }
            }

            # TLS protocol checks remain the same for both versions
            Write-Verbose "Checking TLS protocol versions..."
            $protocols = @(
                @{Name='TLS 1.0'; Required='Disabled'},
                @{Name='TLS 1.1'; Required='Disabled'},
                @{Name='TLS 1.2'; Required='Enabled'}
            )

            foreach ($protocol in $protocols) {
                $protocolPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$($protocol.Name)\Server"
                if (Test-Path $protocolPath) {
                    $enabled = (Get-ItemProperty -Path $protocolPath -ErrorAction SilentlyContinue).Enabled
                    $disabledByDefault = (Get-ItemProperty -Path $protocolPath -ErrorAction SilentlyContinue).DisabledByDefault
                    
                    if ($protocol.Required -eq 'Disabled' -and ($enabled -ne 0 -or $disabledByDefault -ne 1)) {
                        $issues += "$($protocol.Name) is not properly disabled"
                    }
                    elseif ($protocol.Required -eq 'Enabled' -and ($enabled -ne 1 -or $disabledByDefault -ne 0)) {
                        $issues += "$($protocol.Name) is not properly enabled"
                    }
                }
                else {
                    $issues += "$($protocol.Name) settings are not configured"
                }
            }

            return @{
                Issues = $issues
                PolicyExists = $true
            }
        }

        if ($checkResult.Issues.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = "The following issues were found: $($checkResult.Issues -join '; ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking SSL cipher suite configuration: $_"
    }

    return $result
}