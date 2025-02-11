function Handle-Fixes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$WarningsFound,
        
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter()]
        [switch]$Force
    )
    
    Write-Verbose "Processing fixes using global arrays: Checks=$($global:checks.Count), Fixes=$($global:fixes.Count)"
    
    if ($WarningsFound.Count -gt 0) {
        Write-Host "`nProcessing fixes for warnings found..."
        
        foreach ($warning in $WarningsFound) {
            # Look up the fix function from the global $fixes array
            $fixInfo = $global:fixes | Where-Object { $_.Number -eq $warning.Number }
            if (-not $fixInfo) {
                Write-Warning "No fix function found for check number $($warning.Number)"
                continue
            }
            
            # Look up the corresponding check function
            $checkInfo = $global:checks | Where-Object { $_.Number -eq $warning.Number }
            if (-not $checkInfo) {
                Write-Warning "No check function found for number $($warning.Number)"
                continue
            }
 
            Write-Host "$($warning.Number). " -NoNewline
            
            # If Force is specified, automatically proceed with fix
            if ($Force) {
                Write-Host "$($warning.Details). Automatically fixing this issue..." -ForegroundColor Yellow
                $response = 'y'
            } else {
                Write-Host "$($warning.Details). Would you like to fix this issue? (y/N): " -ForegroundColor Yellow -NoNewline
                $response = Read-Host
            }
            
            if ($response -eq 'y') {
                Write-Verbose "Applying fix using $($fixInfo.Function)..."
                
                # Call the fix function with the target server parameter
                try {
                    & $fixInfo.Function -ComputerName $ComputerName -Verbose:$VerbosePreference
                }
                catch {
                    $errorMsg = "Error executing fix for check $($warning.Number)"
                    if ($_.Exception.Message) {
                        $errorMsg += ": " + $_.Exception.Message
                    }
                    Write-Warning $errorMsg
                    continue
                }
                
                Write-Verbose "Fix completed."
                
                # Re-run check to verify fix
                try {
                    $result = & (Get-Command $checkInfo.Function) -ComputerName $ComputerName
                    
                    if ($result.Status -eq "OK") {
                        Write-Host "Verification: Issue has been resolved.`n" -ForegroundColor Green
                    } else {
                        Write-Host "Verification: Issue remains unresolved.`n" -ForegroundColor Red
                    }
                }
                catch {
                    Write-Warning "Failed to verify fix: $($_.Exception.Message)"
                }
            }
        }
    }
} 