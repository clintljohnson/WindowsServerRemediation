function Check-NTLMv1Auth {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 32
        Name = "NTLM Version 1 Authentication"
        Status = "OK"
        Details = "NTLMv1 authentication is properly disabled"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # Check registry for LMCompatibilityLevel
            $ntlmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $ntlmKey = "LMCompatibilityLevel"
            
            $ntlmSetting = Get-ItemProperty -Path $ntlmPath -Name $ntlmKey -ErrorAction SilentlyContinue
            
            # Check if the key exists and return its value
            if ($ntlmSetting) {
                return @{
                    Exists = $true
                    Value = $ntlmSetting.$ntlmKey
                }
            } else {
                return @{
                    Exists = $false
                    Value = $null
                }
            }
        }

        # Evaluate the results
        # LMCompatibilityLevel should be 4 or 5 to disable NTLMv1
        if (-not $checkResult.Exists -or $checkResult.Value -lt 4) {
            $result.Status = "WARNING"
            $result.Details = "NTLMv1 authentication is not properly disabled. Current setting: " + 
                            $(if ($checkResult.Exists) { $checkResult.Value } else { "Not configured" })
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking NTLMv1 authentication settings: $_"
    }

    return $result
} 