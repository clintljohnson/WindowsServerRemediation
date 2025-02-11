function Fix-InstallerPrivileges {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for InstallerPrivileges on $ComputerName"

    try {
        # First check current state
        $currentState = Check-InstallerPrivileges -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - installer privileges are already properly configured"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $hklmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
                $hkcuPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
                $regName = "AlwaysInstallElevated"

                # Create paths if they don't exist
                foreach ($path in @($hklmPath, $hkcuPath)) {
                    if (-not (Test-Path $path)) {
                        New-Item -Path $path -Force | Out-Null
                        Write-Verbose "Created registry path: $path"
                    }
                }

                # Set both values to 0
                Set-ItemProperty -Path $hklmPath -Name $regName -Value 0 -Type DWord
                Set-ItemProperty -Path $hkcuPath -Name $regName -Value 0 -Type DWord
                Write-Verbose "Set AlwaysInstallElevated to 0 in both HKLM and HKCU"

                return $true
            }
            catch {
                Write-Error "Failed to apply fix: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully applied installer privileges fix" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-InstallerPrivileges -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply installer privileges fix"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 