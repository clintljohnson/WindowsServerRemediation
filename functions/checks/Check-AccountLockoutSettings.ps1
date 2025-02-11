function Check-AccountLockoutSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 18
        Name = "Account Lockout Settings"
        Status = "OK"
        Details = "Account lockout settings are properly configured"
        Function = $MyInvocation.MyCommand.Name
    }

    try {
        Write-Verbose "Checking account lockout settings on $ComputerName"

        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "Retrieving account lockout policy"
            $policy = net accounts | Out-String
            
            # Parse the policy output more safely
            $settings = @{
                Duration = 0
                Threshold = 0
                Window = 0
            }
            
            if ($policy) {
                $policyLines = $policy -split "`r`n"
                foreach ($line in $policyLines) {
                    if ($line -match "Lockout duration \(minutes\):\s*(\d+)") { 
                        $settings.Duration = [int]$matches[1] 
                    }
                    elseif ($line -match "Lockout threshold:\s*(\d+)") { 
                        $settings.Threshold = [int]$matches[1] 
                    }
                    elseif ($line -match "Lockout observation window \(minutes\):\s*(\d+)") { 
                        $settings.Window = [int]$matches[1] 
                    }
                }
            }
            
            Write-Verbose "Retrieved settings: Duration=$($settings.Duration), Threshold=$($settings.Threshold), Window=$($settings.Window)"
            return $settings
        }

        # Verify we got valid results
        if ($null -eq $checkResult) {
            throw "Failed to retrieve account lockout settings"
        }
        
        $issues = @()
        
        # Check duration (should be ≥ 30 minutes)
        if ($checkResult.Duration -lt 30) {
            $issues += "Lockout duration ($($checkResult.Duration) mins) should be at least 30 minutes"
        }
        
        # Check threshold (should be ≤ 3 attempts and > 0)
        if ($checkResult.Threshold -eq 0 -or $checkResult.Threshold -gt 3) {
            $issues += "Lockout threshold ($($checkResult.Threshold) attempts) should be between 1 and 3"
        }
        
        # Check window (should be ≥ 30 minutes)
        if ($checkResult.Window -lt 30) {
            $issues += "Lockout window ($($checkResult.Window) mins) should be at least 30 minutes"
        }

        if ($issues.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = $issues -join "; "
        }
        else {
            $result.Details = "Duration=$($checkResult.Duration)m, Threshold=$($checkResult.Threshold), Window=$($checkResult.Window)m"
        }
    }
    catch {
        Write-Verbose "Error in Check-AccountLockoutSettings: $_"
        $result.Status = "WARNING"
        $result.Details = "Error checking account lockout settings on $ComputerName`: $_"
    }

    return $result
}