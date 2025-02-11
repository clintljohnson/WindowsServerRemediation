function Fix-AdminShares {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for Administrative Shares on $ComputerName"

    try {
        # First get the current state using the check function
        $currentState = Check-AdminShares -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - administrative shares are already disabled"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $success = $true
            $modified = @()
            
            try {
                # Remove ADMIN$ and C$ shares using WMI
                Write-Verbose "Removing administrative shares..."
                $shares = Get-WmiObject -Class Win32_Share
                foreach ($share in $shares) {
                    if ($share.Name -in @('ADMIN$', 'C$')) {
                        try {
                            $share.Delete()
                            Write-Verbose "Successfully removed share: $($share.Name)"
                        }
                        catch {
                            Write-Warning "Failed to remove share $($share.Name): $_"
                        }
                    }
                }
                $modified += "Removed ADMIN$ and C$ shares"

                # Disable admin shares in registry
                Write-Verbose "Updating registry settings..."
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }

                # Disable administrative shares
                Set-ItemProperty -Path $regPath -Name "AutoShareServer" -Value 0 -Type DWord
                Set-ItemProperty -Path $regPath -Name "AutoShareWks" -Value 0 -Type DWord
                
                # Additional security settings
                Set-ItemProperty -Path $regPath -Name "RestrictNullSessAccess" -Value 1 -Type DWord
                Set-ItemProperty -Path $regPath -Name "EnableAuthenticateUserSharing" -Value 0 -Type DWord
                Set-ItemProperty -Path $regPath -Name "NullSessionPipes" -Value @() -Type MultiString
                Set-ItemProperty -Path $regPath -Name "NullSessionShares" -Value @() -Type MultiString
                
                $modified += "Updated registry settings to prevent administrative shares"

                # Stop existing connections
                Write-Verbose "Stopping existing connections..."
                $null = net session /delete /y 2>&1
                Start-Sleep -Seconds 2

                # Stop the Server service
                Write-Verbose "Stopping Server service..."
                Stop-Service -Name LanmanServer -Force
                Start-Sleep -Seconds 3

                # Additional registry keys in multiple locations
                Write-Verbose "Adding additional registry preventions..."
                $paths = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
                )

                foreach ($path in $paths) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $path -Name "AutoShareWks" -Value 0 -Type DWord
                    Set-ItemProperty -Path $path -Name "AutoShareServer" -Value 0 -Type DWord
                }

                # Start the Server service
                Write-Verbose "Starting Server service..."
                Start-Service -Name LanmanServer
                $modified += "Restarted Server service to apply changes"
                $modified += "Added additional registry preventions"

                # Double-check shares are gone
                $remainingShares = Get-WmiObject -Class Win32_Share | 
                    Where-Object { $_.Name -in @('ADMIN$', 'C$') }
                
                if ($remainingShares) {
                    Write-Warning "Some administrative shares still exist after removal attempt"
                    $success = $false
                }
            }
            catch {
                Write-Warning "Error during fix operation: $_"
                $success = $false
            }

            return @{
                Success = $success
                Modified = $modified
            }
        }

        if ($result.Success) {
            Write-Host "Successfully applied fixes:" -ForegroundColor Green
            $result.Modified | ForEach-Object { Write-Host "- $_" }
            
            # Verify the fix
            Start-Sleep -Seconds 5  # Give time for changes to take effect
            $verifyResult = Check-AdminShares -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply all fixes"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
}