function Check-CBCCiphers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 27
        Name = "CBC-mode Cipher Support"
        Status = "OK"
        Details = "CBC-mode ciphers are properly disabled"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # First check Windows version
            $osInfo = Get-WmiObject -Class Win32_OperatingSystem
            $isServer2022 = $osInfo.Caption -like "*Server 2022*"
            
            # Different registry paths based on OS version
            $paths = if ($isServer2022) {
                @(
                    # Server 2022 uses different registry structure for cipher configuration
                    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128\CBC',
                    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256\CBC',
                    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES\CBC'
                )
            } else {
                @(
                    # Legacy paths for older Windows Server versions
                    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128\CBC',
                    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256\CBC',
                    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168\CBC'
                )
            }

            # Additional check for Server 2022's default security configuration
            if ($isServer2022) {
                $defaultSecurityEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -Name 'EnableDefaultSecurityConfiguration' -ErrorAction SilentlyContinue
                if ($defaultSecurityEnabled.EnableDefaultSecurityConfiguration -eq 1) {
                    # Server 2022 with default security enabled automatically disables weak ciphers
                    return @{ 
                        CBCEnabled = $false
                        IsServer2022 = $true
                        UsingDefaultSecurity = $true
                    }
                }
            }

            $cbcEnabled = $false
            foreach ($path in $paths) {
                if (Test-Path $path) {
                    $enabled = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).Enabled
                    if ($enabled -ne 0) {
                        $cbcEnabled = $true
                        break
                    }
                } else {
                    # If path doesn't exist, cipher is enabled by default
                    $cbcEnabled = $true
                    break
                }
            }

            return @{ 
                CBCEnabled = $cbcEnabled
                IsServer2022 = $isServer2022
                UsingDefaultSecurity = $false
            }
        }

        if ($checkResult.CBCEnabled) {
            $result.Status = "WARNING"
            if ($checkResult.IsServer2022) {
                $result.Details = "CBC-mode ciphers are enabled. Consider enabling Windows Server 2022's default security configuration or manually disable CBC ciphers"
            } else {
                $result.Details = "CBC-mode ciphers are enabled and should be disabled for improved security"
            }
        } elseif ($checkResult.UsingDefaultSecurity) {
            $result.Details = "CBC-mode ciphers are disabled via Windows Server 2022's default security configuration"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error performing check: $_"
    }

    return $result
} 