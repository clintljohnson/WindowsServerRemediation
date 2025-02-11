function Fix-HMACAlgorithms {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for HMAC Algorithms on $ComputerName"

    try {
        # First verify current state
        $currentState = Check-HMACAlgorithms -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $fixed = $true
            
            # Fix TLS HMAC settings
            try {
                $tlsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
                # Enable only SHA256, SHA384, and SHA512
                $secureHashes = "SHA256,SHA384,SHA512"
                Set-ItemProperty -Path $tlsPath -Name "HashAlgorithms" -Value $secureHashes -Type String
                Write-Verbose "Updated TLS hash algorithms to use SHA-2 family only"
            }
            catch {
                Write-Warning "Failed to update TLS HMAC settings: $_"
                $fixed = $false
            }

            # Fix SMB signing algorithm
            try {
                $smbPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                # Set to SHA256 (2)
                Set-ItemProperty -Path $smbPath -Name "SigningAlgorithm" -Value 2 -Type DWord
                Write-Verbose "Updated SMB signing to use SHA256"
            }
            catch {
                Write-Warning "Failed to update SMB signing algorithm: $_"
                $fixed = $false
            }

            # Fix IPsec policies
            try {
                $ipsecRules = Get-NetIPsecRule
                foreach ($rule in $ipsecRules) {
                    $phase1Auth = Get-NetIPsecPhase1AuthSet -AssociatedNetIPsecRule $rule
                    $phase2Auth = Get-NetIPsecPhase2AuthSet -AssociatedNetIPsecRule $rule
                    
                    if ($phase1Auth.HashAlgorithm -match "MD5|SHA1") {
                        Set-NetIPsecPhase1AuthSet -AssociatedNetIPsecRule $rule -HashAlgorithm SHA256
                    }
                    if ($phase2Auth.HashAlgorithm -match "MD5|SHA1") {
                        Set-NetIPsecPhase2AuthSet -AssociatedNetIPsecRule $rule -HashAlgorithm SHA256
                    }
                }
                Write-Verbose "Updated IPsec policies to use SHA256"
            }
            catch {
                Write-Warning "Failed to update IPsec policies: $_"
                $fixed = $false
            }

            return $fixed
        }

        if ($result) {
            Write-Host "Successfully updated HMAC algorithms to use SHA-2 or stronger" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-HMACAlgorithms -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply all HMAC algorithm fixes"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 