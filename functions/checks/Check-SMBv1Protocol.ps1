function Check-SMBv1Protocol {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 45
        Name = "SMBv1 Protocol Status"
        Status = "OK"
        Details = "SMBv1 protocol is disabled as recommended"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # Initialize results
            $results = @{
                FeatureEnabled = $false
                RegIssues = @()
                Errors = @()
            }

            try {
                # Check Windows Feature status with better error handling
                $featureStatus = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
                $results.FeatureEnabled = $featureStatus.State -eq "Enabled"
            }
            catch {
                $results.Errors += "Unable to check SMB1Protocol feature status: $_"
            }
            
            # Check registry settings
            $regSettings = @(
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                    Name = "SMB1"
                    ExpectedValue = 0
                },
                @{
                    Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
                    Name = "Start"
                    ExpectedValue = 4
                }
            )

            foreach ($setting in $regSettings) {
                try {
                    if (Test-Path $setting.Path) {
                        $value = (Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction Stop).$($setting.Name)
                        if ($null -eq $value -or $value -ne $setting.ExpectedValue) {
                            $results.RegIssues += "Registry value $($setting.Path)\$($setting.Name) is $(if ($null -eq $value) {'not set'} else {"set to $value"}) (should be $($setting.ExpectedValue))"
                        }
                    }
                    else {
                        $results.RegIssues += "Registry path $($setting.Path) does not exist"
                    }
                }
                catch {
                    $results.RegIssues += "Error checking $($setting.Path)\$($setting.Name): $_"
                }
            }

            return $results
        }

        if ($checkResult.Errors.Count -gt 0 -or $checkResult.FeatureEnabled -or $checkResult.RegIssues.Count -gt 0) {
            $result.Status = "WARNING"
            $details = @()
            
            if ($checkResult.Errors.Count -gt 0) {
                $details += $checkResult.Errors
            }
            
            if ($checkResult.FeatureEnabled) {
                $details += "SMBv1 Windows feature is enabled"
            }
            
            if ($checkResult.RegIssues.Count -gt 0) {
                $details += $checkResult.RegIssues
            }
            
            $result.Details = "SMBv1 protocol is not fully disabled: $($details -join '; ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error performing SMBv1 protocol check: $_"
    }

    return $result
} 