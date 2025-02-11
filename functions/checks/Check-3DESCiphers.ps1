function Check-3DESCiphers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 37
        Name = "3DES Cipher Suites"
        Status = "OK"
        Details = "3DES cipher suites are properly disabled"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # Check registry paths for 3DES ciphers
            $paths = @(
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"
                "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168"
            )
            
            $issues = @()
            
            foreach ($path in $paths) {
                if (Test-Path $path) {
                    $enabled = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).Enabled
                    if ($enabled -ne 0) {
                        $issues += "3DES is enabled at path: $path"
                    }
                }
            }

            # Check if 3DES is in SSL Cipher Suite order
            $cipherOrder = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -ErrorAction SilentlyContinue).'Functions'
            if ($cipherOrder -match 'TLS_RSA_WITH_3DES') {
                $issues += "3DES ciphers found in SSL cipher suite order"
            }

            return @{
                HasIssues = $issues.Count -gt 0
                Issues = $issues
            }
        }

        if ($checkResult.HasIssues) {
            $result.Status = "WARNING"
            $result.Details = "3DES cipher suites are enabled: $($checkResult.Issues -join '; ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking 3DES cipher settings: $_"
    }

    return $result
} 