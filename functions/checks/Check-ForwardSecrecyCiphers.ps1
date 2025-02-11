function Check-ForwardSecrecyCiphers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 30
        Name = "TLS Forward Secrecy Ciphers"
        Status = "OK"
        Details = "Forward secrecy cipher configuration is secure"
    }

    try {
        $cipherConfig = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                # Get Windows version information
                $osInfo = Get-WmiObject -Class Win32_OperatingSystem
                $isServer2022 = $osInfo.Caption -like "*Server 2022*"
                Write-Verbose "OS Version: $($osInfo.Caption)"

                # For Server 2022, we need to check the cipher suite order
                if ($isServer2022) {
                    $cipherOrder = Get-TlsCipherSuite | Sort-Object -Property Priority
                    Write-Verbose "Found $($cipherOrder.Count) cipher suites in order"

                    # Get enabled ciphers (all ciphers are technically "enabled" in 2022)
                    $enabledCiphers = $cipherOrder | Where-Object {
                        $_.Name -notlike "*NULL*" -and
                        $_.Name -notlike "*RC4*" -and
                        $_.Name -notlike "*DES*" -and
                        $_.Name -notlike "*MD5*" -and
                        $_.Name -notlike "*3DES*"
                    }
                } else {
                    # Server 2019 and earlier - check registry for enabled ciphers
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
                    $cipherOrder = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -ErrorAction SilentlyContinue

                    if ($cipherOrder) {
                        $enabledCiphers = $cipherOrder.Functions.Split(',') | ForEach-Object {
                            @{ Name = $_.Trim() }
                        }
                    } else {
                        # If no explicit order is set, get enabled ciphers from SCHANNEL
                        $enabledCiphers = @()
                        Get-ChildItem $regPath -ErrorAction SilentlyContinue | ForEach-Object {
                            $cipherName = Split-Path $_.PSPath -Leaf
                            $enabled = Get-ItemProperty -Path "$regPath\$cipherName" -Name "Enabled" -ErrorAction SilentlyContinue
                            if ($enabled -and $enabled.Enabled -eq 1) {
                                $enabledCiphers += @{ Name = $cipherName }
                            }
                        }
                    }
                }

                # Check for forward secrecy ciphers
                $fsCiphers = $enabledCiphers | Where-Object {
                    ($_.Name -like "*ECDHE*" -or $_.Name -like "*DHE*") -and
                    ($_.Name -like "*_AES_*")
                }
                
                # Check for non-FS ciphers
                $nonFsCiphers = $enabledCiphers | Where-Object {
                    $_.Name -like "TLS_RSA*" -and
                    $_.Name -notlike "*ECDHE*" -and
                    $_.Name -notlike "*DHE*"
                }

                @{
                    FSCiphers = $fsCiphers
                    NonFSCiphers = $nonFsCiphers
                    TotalEnabled = $enabledCiphers.Count
                    IsServer2022 = $isServer2022
                    FSNames = @($fsCiphers | ForEach-Object { $_.Name })
                    NonFSNames = @($nonFsCiphers | ForEach-Object { $_.Name })
                }
            }
            catch {
                throw "Error in cipher suite configuration: $_"
            }
        }

        # Required forward secrecy ciphers that should be enabled
        $requiredCiphers = @(
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
        )

        $missingRequired = $requiredCiphers | Where-Object {
            $cipher = $_
            $cipher -notin $cipherConfig.FSNames
        }

        if ($missingRequired) {
            $result.Status = "WARNING"
            $result.Details = "Missing required forward secrecy ciphers: $($missingRequired -join ', ')"
        }
        elseif ($cipherConfig.NonFSNames.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = "Non-forward secrecy ciphers are present: $($cipherConfig.NonFSNames -join ', ')"
        }
        else {
            $result.Details = "Forward secrecy ciphers configured correctly. Using: $($cipherConfig.FSNames -join ', ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking forward secrecy cipher suites: $_"
        Write-Verbose "Error in Check-ForwardSecrecyCiphers: $_"
    }

    return $result
} 