function Fix-CreateToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for Create Token Object right on $ComputerName"

    try {
        # First check current state
        $currentState = Check-CreateToken -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $tempFile = [System.IO.Path]::GetTempFileName()
                secedit /export /cfg $tempFile /quiet
                
                # Remove all accounts from the privilege
                $content = Get-Content $tempFile
                $content = $content -replace 'SeCreateTokenPrivilege = .*', 'SeCreateTokenPrivilege ='
                $content | Set-Content $tempFile
                
                secedit /configure /db secedit.sdb /cfg $tempFile /areas USER_RIGHTS /quiet
                return $true
            }
            catch {
                Write-Error "Failed to apply fix: $_"
                return $false
            }
            finally {
                if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
                if (Test-Path "secedit.sdb") { Remove-Item "secedit.sdb" -Force }
            }
        }

        if ($result) {
            Write-Host "Successfully removed all accounts from Create Token Object right" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-CreateToken -ComputerName $ComputerName
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
        }
        
        Write-Warning "Failed to apply or verify fix"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 