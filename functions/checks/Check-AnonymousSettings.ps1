function Check-AnonymousSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 21
        Name = "Anonymous Access Settings"
        Status = "OK"
        Details = "Anonymous access settings are properly restricted"
    }

    try {
        # First get OS version to determine appropriate settings
        $osInfo = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-WmiObject -Class Win32_OperatingSystem
        }
        
        Write-Verbose "Detected OS: $($osInfo.Caption)"

        # Check various anonymous access registry settings remotely
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($osVersion)

            # Base settings that apply to all versions
            $settings = @(
                @{
                    Path = "SYSTEM\CurrentControlSet\Control\Lsa"
                    Name = "EveryoneIncludesAnonymous"
                    Expected = 0
                    Description = "Controls whether the Everyone group includes anonymous users"
                },
                @{
                    Path = "SYSTEM\CurrentControlSet\Control\Lsa"
                    Name = "RestrictAnonymous"
                    Expected = 1
                    Description = "Restricts anonymous access to named pipes and shares"
                },
                @{
                    Path = "SYSTEM\CurrentControlSet\Control\Lsa"
                    Name = "RestrictAnonymousSAM"
                    Expected = 1
                    Description = "Restricts anonymous access to SAM accounts and shares"
                }
            )

            # Additional settings for Server 2022 and newer
            if ($osVersion -match "2022|2025") {
                $settings += @{
                    Path = "SYSTEM\CurrentControlSet\Control\Lsa"
                    Name = "RestrictRemoteSAM"
                    Expected = "O:BAG:BAD:(A;;RC;;;BA)"  # Allows only Administrators remote access to SAM
                    Description = "Controls remote SAM access restrictions"
                }
            }

            $issues = @()
            foreach ($setting in $settings) {
                try {
                    $regKey = Get-ItemProperty -Path "HKLM:\$($setting.Path)" -Name $setting.Name -ErrorAction Stop
                    $actualValue = $regKey.$($setting.Name)
                    Write-Verbose "Checking $($setting.Name): Expected=$($setting.Expected), Actual=$actualValue"
                    
                    if ($actualValue -ne $setting.Expected) {
                        $issues += "$($setting.Name) is not set correctly (Current: $actualValue, Expected: $($setting.Expected)) - $($setting.Description)"
                    }
                }
                catch {
                    $issues += "$($setting.Name) registry value not found - $($setting.Description)"
                }
            }

            # Check Network Access restrictions (specific to newer versions)
            try {
                $networkAccess = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -ErrorAction Stop
                if ($networkAccess.RestrictNullSessAccess -ne 1) {
                    $issues += "RestrictNullSessAccess is not properly configured (Should be enabled)"
                }
            }
            catch {
                $issues += "Unable to verify RestrictNullSessAccess setting"
            }

            return @{
                Issues = $issues
                Values = $settings | ForEach-Object {
                    try {
                        $value = (Get-ItemProperty -Path "HKLM:\$($_.Path)" -Name $_.Name -ErrorAction Stop).$($_.Name)
                        return "$($_.Name)=$value"
                    }
                    catch {
                        return "$($_.Name)=NotFound"
                    }
                }
            }
        } -ArgumentList $osInfo.Caption

        if ($checkResult.Issues.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = "The following anonymous access settings need attention: $($checkResult.Issues -join '; ')"
            Write-Verbose "Current values: $($checkResult.Values -join ', ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking anonymous settings: $_"
    }

    return $result
} 