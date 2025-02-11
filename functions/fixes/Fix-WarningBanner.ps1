function Fix-WarningBanner {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for WarningBanner on $ComputerName"

    try {
        # First check current state
        $currentState = Check-WarningBanner -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - warning banner is already properly configured"
            return $true
        }

        # Default warning banner text (without explicit \r)
        $defaultCaption = "Security Warning"
        $defaultText = "This system is for authorized use only. By using this system, you agree to comply with all security policies and monitoring.Unauthorized access or use of this system is prohibited and may result in disciplinary action and/or criminal prosecution.All activities on this system may be monitored and recorded."

        Write-Verbose "Applying warning banner configuration to $ComputerName"
        
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($caption, $text)
            
            try {
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                
                # Ensure the path exists
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }

                Write-Verbose "Setting legalnoticecaption"
                Set-ItemProperty -Path $regPath -Name "legalnoticecaption" -Value $caption -Force
                
                Write-Verbose "Setting legalnoticetext"
                Set-ItemProperty -Path $regPath -Name "legalnoticetext" -Value $text -Force
                
                return $true
            }
            catch {
                Write-Error "Failed to set registry values: $_"
                return $false
            }
        } -ArgumentList $defaultCaption, $defaultText

        if ($result) {
            Write-Host "Successfully configured warning banner" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-WarningBanner -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed: $($verifyResult.Details)"
                return $false
            }
        }
        
        Write-Warning "Failed to apply warning banner configuration"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 