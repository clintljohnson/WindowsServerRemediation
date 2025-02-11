function Check-HMACAlgorithms {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 35
        Name = "HMAC Algorithm Security"
        Status = "OK"
        Details = "All HMAC algorithms are using SHA-2 or stronger"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $weakHMACs = @()
            
            # Check TLS HMAC settings
            $tlsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
            $tlsHMACs = Get-ItemProperty -Path $tlsPath -Name "HashAlgorithms" -ErrorAction SilentlyContinue
            
            if ($tlsHMACs) {
                if ($tlsHMACs.HashAlgorithms -match "MD5" -or $tlsHMACs.HashAlgorithms -match "SHA1") {
                    $weakHMACs += "TLS/SSL"
                }
            }

            # Check SMB signing algorithm
            $smbPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            $smbAlgo = Get-ItemProperty -Path $smbPath -Name "SigningAlgorithm" -ErrorAction SilentlyContinue
            
            if ($smbAlgo) {
                if ($smbAlgo.SigningAlgorithm -lt 2) { # 0=MD5, 1=SHA1, 2=SHA256
                    $weakHMACs += "SMB Signing"
                }
            }

            # Check IPsec settings
            try {
                $ipsecPolicies = Get-NetIPsecRule | ForEach-Object {
                    $phase1Auth = Get-NetIPsecPhase1AuthSet -AssociatedNetIPsecRule $_ -ErrorAction Stop
                    $phase2Auth = Get-NetIPsecPhase2AuthSet -AssociatedNetIPsecRule $_ -ErrorAction Stop
                    
                    if ($phase1Auth.HashAlgorithm -match "MD5|SHA1" -or 
                        $phase2Auth.HashAlgorithm -match "MD5|SHA1") {
                        return $_
                    }
                }
                
                if ($ipsecPolicies) {
                    $weakHMACs += "IPsec"
                }
            }
            catch {
                Write-Verbose "Error checking IPsec policies: $_"
            }

            return @{
                WeakHMACs = $weakHMACs
                Details = if ($weakHMACs) { 
                    "Weak HMAC algorithms found in: $($weakHMACs -join ', ')"
                } else {
                    "No weak HMAC algorithms detected"
                }
            }
        }

        if ($checkResult.WeakHMACs.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = $checkResult.Details
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking HMAC algorithms: $_"
    }

    return $result
} 