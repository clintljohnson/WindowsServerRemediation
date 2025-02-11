function Check-StaticKeyCiphers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 33
        Name = "Static Key Cipher Suites in TLS"
        Status = "OK"
        Details = "No static key cipher suites are enabled"
    }

    try {
        Write-Verbose "Checking static key cipher suites configuration on $ComputerName"
        
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # Check registry for enabled cipher suites
            $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"
            $staticCiphers = @()
            
            # Get SSL Cipher Suite order
            $cipherOrder = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -ErrorAction SilentlyContinue).Functions
            
            if ($cipherOrder) {
                # Check for static RSA cipher suites
                $staticCiphers = $cipherOrder -split ',' | Where-Object { $_ -like "*TLS_RSA_*" }
            }
            
            return @{
                StaticCiphersFound = $staticCiphers
                HasStaticCiphers = ($staticCiphers.Count -gt 0)
            }
        }

        if ($checkResult.HasStaticCiphers) {
            $result.Status = "WARNING"
            $result.Details = "Static key cipher suites are enabled: $($checkResult.StaticCiphersFound -join ', ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error performing check: $_"
    }

    return $result
} 