function Fix-TLSProtocols {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for TLS Protocols on $ComputerName"

    try {
        # First verify current state
        $currentState = Check-TLSProtocols -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # First determine Windows Server version
            $osVersion = Get-WmiObject -Class Win32_OperatingSystem
            $isServer2022 = $osVersion.Caption -like "*Server 2022*"
            
            Write-Verbose "Detected OS: $($osVersion.Caption)"

            if ($isServer2022) {
                Write-Verbose "Configuring Server 2022 TLS settings"
                
                # Ensure weak TLS is disabled
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' `
                    -Name 'EnableWeakTLS' -Value 0 -Type DWord
                
                # Enable TLS 1.2 explicitly (although it's enabled by default)
                $tls12Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2'
                foreach ($side in @('Client', 'Server')) {
                    $path = "$tls12Path\$side"
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name 'Enabled' -Value 1 -Type DWord
                    Set-ItemProperty -Path $path -Name 'DisabledByDefault' -Value 0 -Type DWord
                }
            } else {
                Write-Verbose "Configuring pre-2022 TLS settings"
                
                $protocols = @{
                    'SSL 2.0' = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0'
                    'SSL 3.0' = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0'
                    'TLS 1.0' = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0'
                    'TLS 1.1' = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1'
                }

                foreach ($protocol in $protocols.Keys) {
                    $basePath = $protocols[$protocol]
                    
                    foreach ($side in @('Client', 'Server')) {
                        $path = "$basePath\$side"
                        
                        if (-not (Test-Path $path)) {
                            New-Item -Path $path -Force | Out-Null
                        }
                        
                        Set-ItemProperty -Path $path -Name 'Enabled' -Value 0 -Type DWord
                        Set-ItemProperty -Path $path -Name 'DisabledByDefault' -Value 1 -Type DWord
                    }
                }
            }
            
            return $true
        }

        if ($result) {
            Write-Host "Successfully configured TLS protocol settings" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-TLSProtocols -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 