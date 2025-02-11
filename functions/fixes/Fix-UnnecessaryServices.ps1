function Fix-UnnecessaryServices {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for Unnecessary Services on $ComputerName"

    try {
        # First get the current state using the check function
        $currentState = Check-UnnecessaryServices -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $unnecessaryServices = @(
                    "SNMP",
                    "TlntSvr",
                    "FTPSVC",
                    "SharedAccess",
                    "simptcp",
                    "Browser",
                    "RemoteRegistry"
                )

                $disabledServices = @()
                
                foreach ($serviceName in $unnecessaryServices) {
                    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                    
                    if ($service -and $service.Status -eq 'Running') {
                        Stop-Service -Name $serviceName -Force
                        Set-Service -Name $serviceName -StartupType Disabled
                        $disabledServices += $serviceName
                        Write-Verbose "Disabled service: $serviceName"
                    }
                }

                return @{
                    Success = $true
                    DisabledServices = $disabledServices
                }
            }
            catch {
                Write-Error "Failed to apply fix: $_"
                return @{
                    Success = $false
                    DisabledServices = @()
                }
            }
        }

        if ($result.Success) {
            if ($result.DisabledServices.Count -gt 0) {
                Write-Host "Successfully disabled services: $($result.DisabledServices -join ', ')" -ForegroundColor Green
            }
            
            # Verify the fix
            $verifyResult = Check-UnnecessaryServices -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to disable unnecessary services"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 