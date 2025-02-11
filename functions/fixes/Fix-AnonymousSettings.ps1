function Fix-AnonymousSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for AnonymousSettings on $ComputerName"

    try {
        # First get OS version to determine appropriate settings
        $osInfo = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-WmiObject -Class Win32_OperatingSystem
        }
        Write-Verbose "Detected OS: $($osInfo.Caption)"

        # First get the current state using the check function
        $currentState = Check-AnonymousSettings -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        Write-Verbose "Current state: $($currentState.Details)"

        # Use Invoke-Command for remote execution with error handling
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $success = $true
            $messages = @()

            # Define registry paths and values
            $settings = @(
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                    Name = "EveryoneIncludesAnonymous"
                    Value = 0
                    Type = "DWord"
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                    Name = "RestrictAnonymous"
                    Value = 1
                    Type = "DWord"
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                    Name = "RestrictAnonymousSAM"
                    Value = 1
                    Type = "DWord"
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                    Name = "RestrictRemoteSAM"
                    Value = "O:BAG:BAD:(A;;RC;;;BA)"
                    Type = "String"
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                    Name = "RestrictNullSessAccess"
                    Value = 1
                    Type = "DWord"
                }
            )

            foreach ($setting in $settings) {
                try {
                    # Ensure path exists
                    if (-not (Test-Path $setting.Path)) {
                        New-Item -Path $setting.Path -Force | Out-Null
                        $messages += "Created registry path: $($setting.Path)"
                    }

                    # Try direct registry modification first
                    try {
                        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
                        $messages += "Successfully set $($setting.Name) to $($setting.Value)"
                    }
                    catch {
                        # Fallback to using reg.exe
                        $regPath = $setting.Path.Replace('HKLM:\', 'HKLM\')
                        $regType = if ($setting.Type -eq 'String') { 'REG_SZ' } else { 'REG_DWORD' }
                        $regValue = if ($setting.Type -eq 'String') { "`"$($setting.Value)`"" } else { $setting.Value }
                        
                        $regCommand = "reg.exe add `"$regPath`" /v $($setting.Name) /t $regType /d $regValue /f"
                        $regResult = cmd.exe /c $regCommand 2>&1
                        $messages += "Used reg.exe to set $($setting.Name): $regResult"
                    }

                    # Verify the change
                    $newValue = (Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction Stop).$($setting.Name)
                    if ($newValue -ne $setting.Value) {
                        throw "Value verification failed. Expected: $($setting.Value), Got: $newValue"
                    }
                }
                catch {
                    $success = $false
                    $messages += "Failed to set $($setting.Name): $_"
                }
            }

            return @{
                Success = $success
                Messages = $messages
            }
        }

        # Process results
        $result.Messages | ForEach-Object { Write-Verbose $_ }

        if ($result.Success) {
            Write-Host "Successfully configured anonymous access settings" -ForegroundColor Green
            
            # Verify the fix
            Start-Sleep -Seconds 2  # Allow time for changes to propagate
            $verifyResult = Check-AnonymousSettings -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed: $($verifyResult.Details)"
                return $false
            }
        }
        else {
            Write-Warning "Failed to apply some settings"
            return $false
        }
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 