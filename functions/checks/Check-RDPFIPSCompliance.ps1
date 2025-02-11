function Check-RDPFIPSCompliance {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 34
        Name = "RDP FIPS 140-2 Compliance"
        Status = "OK"
        Details = "RDP security is properly configured for FIPS 140-2 compliance"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # Get OS version first
            $osInfo = Get-WmiObject -Class Win32_OperatingSystem
            $isServer2019OrLower = [version]$osInfo.Version -lt [version]"10.0.20348"

            # Check RDP settings
            $rdpSettings = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue
            
            # Check TLS 1.2 settings if Server 2019 or lower
            $tls12Enabled = $true
            if ($isServer2019OrLower) {
                $tlsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
                $tls12Settings = Get-ItemProperty -Path $tlsPath -ErrorAction SilentlyContinue
                $tls12Enabled = ($tls12Settings.Enabled -eq 1) -and ($tls12Settings.DisabledByDefault -eq 0)
            }

            # Check cipher suites if Server 2019 or lower
            $cipherSuitesOK = $true
            if ($isServer2019OrLower) {
                $cipherConfig = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -ErrorAction SilentlyContinue
                $requiredSuites = @(
                    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
                )
                
                if ($cipherConfig) {
                    $configuredSuites = $cipherConfig.Functions -split ','
                    $cipherSuitesOK = $requiredSuites | ForEach-Object { $configuredSuites -contains $_ }
                } else {
                    $cipherSuitesOK = $false
                }
            }

            @{
                MinEncryptionLevel = $rdpSettings.MinEncryptionLevel
                SecurityLayer = $rdpSettings.SecurityLayer
                TLS12Enabled = $tls12Enabled
                CipherSuitesOK = $cipherSuitesOK
                IsServer2019OrLower = $isServer2019OrLower
                OSVersion = $osInfo.Version
            }
        }

        $issues = @()

        if ($checkResult.MinEncryptionLevel -lt 4) {
            $issues += "RDP encryption level is not set to FIPS Compliant (Level 4)"
        }

        if ($checkResult.SecurityLayer -ne 2) {
            $issues += "RDP security layer is not set to SSL/TLS only (Level 2)"
        }

        if ($checkResult.IsServer2019OrLower) {
            if (-not $checkResult.TLS12Enabled) {
                $issues += "TLS 1.2 is not properly enabled (required for Server 2019 and lower)"
            }
            
            if (-not $checkResult.CipherSuitesOK) {
                $issues += "Required cipher suites for RDP are not properly configured"
            }
        }

        if ($issues.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = "RDP FIPS compliance issues found: $($issues -join '; ')"
        }

        Write-Verbose "OS Version: $($checkResult.OSVersion)"
        Write-Verbose "Server 2019 or lower: $($checkResult.IsServer2019OrLower)"
        Write-Verbose "Check result: $($result.Status)"
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking RDP FIPS compliance: $_"
    }

    return $result
} 