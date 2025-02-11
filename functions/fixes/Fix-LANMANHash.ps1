function Fix-LANMANHash {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for LANMANHash on $ComputerName"

    try {
        # First check current state
        $currentState = Check-LANMANHash -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - LANMAN hash is already properly configured"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                $regName = "NoLMHash"

                Write-Verbose "Setting NoLMHash registry value to 1"
                Set-ItemProperty -Path $regPath -Name $regName -Value 1 -Type DWord -Force
                
                # Verify the change was applied
                $newValue = (Get-ItemProperty -Path $regPath -Name $regName).$regName
                return $newValue -eq 1
            }
            catch {
                Write-Error "Failed to apply fix: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully disabled LANMAN hash" -ForegroundColor Green
            
            # Verify the fix using the check function
            $verifyResult = Check-LANMANHash -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to disable LANMAN hash"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 