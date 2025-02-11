function Check-TLSProtocols {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 26
        Name = "SSL/TLS Protocol Versions"
        Status = "OK"
        Details = "All SSL/TLS protocols below version 1.2 are disabled"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # First determine Windows Server version
            $osVersion = Get-WmiObject -Class Win32_OperatingSystem
            $isServer2022 = $osVersion.Caption -like "*Server 2022*"
            
            Write-Verbose "Detected OS: $($osVersion.Caption)"

            # Registry paths for SSL/TLS protocols
            $protocols = @{
                'SSL 2.0' = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0'
                'SSL 3.0' = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0'
                'TLS 1.0' = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0'
                'TLS 1.1' = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1'
            }

            $issues = @()
            
            if ($isServer2022) {
                # For Server 2022, check the default security configuration
                $securityConfig = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -Name 'EnableWeakTLS' -ErrorAction SilentlyContinue
                
                if ($securityConfig.EnableWeakTLS -eq 1) {
                    $issues += "Weak TLS protocols enabled via EnableWeakTLS setting"
                }
            } else {
                # For older servers, check individual protocol settings
                foreach ($protocol in $protocols.Keys) {
                    $clientPath = "$($protocols[$protocol])\Client"
                    $serverPath = "$($protocols[$protocol])\Server"
                    
                    # Check if protocol is enabled on client side
                    if (Test-Path $clientPath) {
                        $enabled = (Get-ItemProperty -Path $clientPath -ErrorAction SilentlyContinue).Enabled
                        if ($enabled -ne 0) {
                            $issues += "$protocol client"
                        }
                    }
                    
                    # Check if protocol is enabled on server side
                    if (Test-Path $serverPath) {
                        $enabled = (Get-ItemProperty -Path $serverPath -ErrorAction SilentlyContinue).Enabled
                        if ($enabled -ne 0) {
                            $issues += "$protocol server"
                        }
                    }
                }
            }

            return @{
                Issues = $issues
                IsServer2022 = $isServer2022
            }
        }

        if ($checkResult.Issues.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = "The following issues were found: $($checkResult.Issues -join ', ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error performing check: $_"
    }

    return $result
} 