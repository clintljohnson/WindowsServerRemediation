# Add function documentation
<#
.SYNOPSIS
    Removes anonymous pipe access settings.
.DESCRIPTION
    Removes the NullSessionPipes registry value to prevent anonymous access to named pipes.
    Registry path: HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
.PARAMETER ComputerName
    The remote computer to configure.
#>

function Fix-AnonymousPipes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for AnonymousPipes on $ComputerName"

    try {
        # Add connectivity test
        if (-not (Test-Connection -ComputerName $ComputerName -Quiet -Count 1)) {
            Write-Error "Cannot connect to $ComputerName"
            return $false
        }

        # First get the current state using the check function
        $currentState = Check-AnonymousPipes -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                $regName = "NullSessionPipes"

                Write-Verbose "Checking current registry value"
                $currentValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
                
                if ($currentValue) {
                    Write-Verbose "Current NullSessionPipes value: $($currentValue.NullSessionPipes)"
                    Write-Verbose "Removing NullSessionPipes registry value"
                    Remove-ItemProperty -Path $regPath -Name $regName -Force
                    Write-Verbose "Registry value removed successfully"
                } else {
                    Write-Verbose "NullSessionPipes value not found - no action needed"
                }
                return $true
            }
            catch {
                Write-Error "Failed to apply fix: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully removed anonymous pipe access settings" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-AnonymousPipes -ComputerName $ComputerName
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply fix"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 