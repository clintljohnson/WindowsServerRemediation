function Fix-NTLMv1Auth {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for NTLMv1 authentication on $ComputerName"

    try {
        # First verify current state
        $currentState = Check-NTLMv1Auth -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - NTLMv1 authentication is already properly configured"
            return $true
        }

        # Apply the fix
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $ntlmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                $ntlmKey = "LMCompatibilityLevel"
                
                # Set LMCompatibilityLevel to 5 (most secure)
                # 5 = Send NTLMv2 response only\refuse LM & NTLM
                Set-ItemProperty -Path $ntlmPath -Name $ntlmKey -Value 5 -Type DWord -Force
                
                Write-Verbose "Set LMCompatibilityLevel to 5"
                return $true
            }
            catch {
                Write-Error "Failed to set NTLMv1 authentication settings: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully disabled NTLMv1 authentication" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-NTLMv1Auth -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply NTLMv1 authentication fix"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 