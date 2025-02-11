function Fix-CBCCiphers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for CBC-mode ciphers on $ComputerName"

    try {
        $currentState = Check-CBCCiphers -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - CBC-mode ciphers are already disabled"
            return $true
        }

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # Check Windows version
            $osInfo = Get-WmiObject -Class Win32_OperatingSystem
            $isServer2022 = $osInfo.Caption -like "*Server 2022*"

            if ($isServer2022) {
                Write-Verbose "Detected Windows Server 2022"
                
                # Offer to enable default security configuration
                $enableDefault = $true  # Default to yes for automation
                if ($enableDefault) {
                    Write-Verbose "Enabling Windows Server 2022 default security configuration"
                    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' `
                                   -Name 'EnableDefaultSecurityConfiguration' `
                                   -Value 1 `
                                   -Type DWord
                    return $true
                }
            }

            # If not Server 2022 or if default security is not desired, manually configure paths
            $paths = if ($isServer2022) {
                @(
                    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128\CBC',
                    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256\CBC',
                    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES\CBC'
                )
            } else {
                @(
                    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128\CBC',
                    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256\CBC',
                    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168\CBC'
                )
            }

            try {
                foreach ($path in $paths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "Enabled" -Value 0 -Type DWord
                    Write-Verbose "Disabled CBC cipher at path: $path"
                }
                return $true
            }
            catch {
                Write-Error "Failed to disable CBC ciphers: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully configured CBC-mode ciphers" -ForegroundColor Green
            
            $verifyResult = Check-CBCCiphers -ComputerName $ComputerName
            
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