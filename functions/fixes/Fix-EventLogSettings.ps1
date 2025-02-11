function Fix-EventLogSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for Event Log Settings on $ComputerName"

    try {
        # First check current state
        $currentState = Check-EventLogSettings -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $logs = @(
                @{ Name = 'Security'; Size = 1073741824 },    # 1GB in bytes
                @{ Name = 'Application'; Size = 104857600 },   # 100MB in bytes
                @{ Name = 'System'; Size = 104857600 }        # 100MB in bytes
            )
            $success = $true

            foreach ($log in $logs) {
                Write-Verbose "Configuring $($log.Name) log..."
                try {
                    # Use wevtutil instead of Get-WinEvent for modifying log settings
                    $result = wevtutil.exe set-log $log.Name /maxsize:$($log.Size)
                    if ($LASTEXITCODE -eq 0) {
                        Write-Verbose "Successfully configured $($log.Name) log size to $($log.Size) bytes"
                    } else {
                        Write-Warning "Failed to configure $($log.Name) log with exit code $LASTEXITCODE"
                        $success = $false
                    }
                }
                catch {
                    Write-Warning "Failed to configure $($log.Name) log: $_"
                    $success = $false
                }
            }
            return $success
        }

        if ($result) {
            Write-Host "Successfully configured event log settings" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-EventLogSettings -ComputerName $ComputerName
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
        }
        
        Write-Warning "Failed to apply or verify event log settings"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 