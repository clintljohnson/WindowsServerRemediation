function Fix-RemoteRegistry {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for Remote Registry on $ComputerName"

    try {
        # First check current state
        $currentState = Check-RemoteRegistry -ComputerName $ComputerName
        Write-Verbose "Initial state: $($currentState.Status) - $($currentState.Details)"
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - Remote Registry is already properly configured"
            return $true
        }

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                # Check if Remote Registry service exists
                $service = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
                if ($service) {
                    Write-Verbose "Found Remote Registry service, current status: $($service.Status)"
                    Write-Verbose "Attempting to stop Remote Registry service..."
                    Stop-Service -Name "RemoteRegistry" -Force -ErrorAction Stop
                    Write-Verbose "Service stopped successfully"
                    
                    Write-Verbose "Setting service startup type to Disabled..."
                    Set-Service -Name "RemoteRegistry" -StartupType Disabled
                    Write-Verbose "Service disabled successfully"
                }

                $paths = @(
                    "SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg",
                    "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Remote Registry"
                )
                
                foreach ($path in $paths) {
                    Write-Verbose "Processing registry path: $path"
                    if (Test-Path "HKLM:\$path") {
                        Write-Verbose "Path exists, attempting to remove..."
                        try {
                            Remove-Item -Path "HKLM:\$path" -Recurse -Force
                            Write-Verbose "Successfully removed path: $path"
                        }
                        catch {
                            Write-Warning "Failed to remove path $path : $_"
                            throw
                        }
                    }
                    else {
                        Write-Verbose "Path does not exist: $path"
                    }
                }
                
                return $true
            }
            catch {
                Write-Error "Failed to apply fix: $_"
                return $false
            }
        } -ErrorAction Stop

        if ($result) {
            Write-Host "Successfully applied Remote Registry fixes" -ForegroundColor Green
            
            Write-Verbose "Waiting 5 seconds before verification..."
            Start-Sleep -Seconds 5
            
            # Verify the fix
            $verifyResult = Check-RemoteRegistry -ComputerName $ComputerName
            Write-Verbose "Verification result: $($verifyResult.Status) - $($verifyResult.Details)"
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed: $($verifyResult.Details)"
                return $false
            }
        }
        
        Write-Warning "Failed to apply Remote Registry fixes"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 