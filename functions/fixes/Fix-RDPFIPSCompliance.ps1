function Fix-RDPFIPSCompliance {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for RDP FIPS compliance on $ComputerName"

    try {
        # First check current state
        $currentState = Check-RDPFIPSCompliance -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - RDP FIPS settings are already compliant"
            return $true
        }

        # Get OS version information first
        $osInfo = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-WmiObject -Class Win32_OperatingSystem
        }
        
        $isServer2019OrLower = [version]$osInfo.Version -lt [version]"10.0.20348"
        Write-Verbose "Detected OS Version: $($osInfo.Version) (Server 2019 or lower: $isServer2019OrLower)"

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($isServer2019OrLower)
            
            try {
                # For Server 2019 and lower, we need to ensure proper cipher suites first
                if ($isServer2019OrLower) {
                    Write-Verbose "Configuring RDP cipher suites for Server 2019 compatibility..."
                    
                    # Enable required cipher suites for RDP
                    $cipherSuites = @(
                        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
                    )
                    
                    $currentCipherSuites = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -ErrorAction SilentlyContinue
                    
                    if (-not $currentCipherSuites) {
                        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Force | Out-Null
                    }
                    
                    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' `
                        -Name 'Functions' -Value ($cipherSuites -join ',')
                }

                # Set RDP encryption level to FIPS
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
                    -Name "MinEncryptionLevel" -Value 4 -Type DWord
                Write-Verbose "Set RDP encryption level to FIPS compliant (4)"

                # Set RDP security layer to SSL/TLS
                Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
                    -Name "SecurityLayer" -Value 2 -Type DWord
                Write-Verbose "Set RDP security layer to SSL/TLS only (2)"

                # For Server 2019, we'll also explicitly enable TLS 1.2
                if ($isServer2019OrLower) {
                    Write-Verbose "Ensuring TLS 1.2 is enabled for Server 2019..."
                    $tlsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
                    if (-not (Test-Path $tlsPath)) {
                        New-Item -Path $tlsPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $tlsPath -Name 'Enabled' -Value 1 -Type DWord
                    Set-ItemProperty -Path $tlsPath -Name 'DisabledByDefault' -Value 0 -Type DWord
                }

                # Restart RDP-related services
                Write-Verbose "Restarting RDP services..."
                Restart-Service -Name "TermService" -Force
                Start-Sleep -Seconds 2  # Brief pause to ensure service dependencies are handled
                Restart-Service -Name "UmRdpService" -Force
                Write-Verbose "RDP services have been restarted"

                return $true
            }
            catch {
                Write-Error "Failed to apply RDP FIPS compliance settings: $_"
                return $false
            }
        } -ArgumentList $isServer2019OrLower

        if ($result) {
            Write-Host "Successfully applied RDP FIPS compliance settings" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-RDPFIPSCompliance -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed - RDP FIPS compliance settings are correct"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply RDP FIPS compliance settings"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 