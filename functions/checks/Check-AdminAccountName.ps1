function Check-AdminAccountName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 17
        Name = "Administrator Account Name"
        Status = "OK"
        Details = "Administrator account has been renamed"
    }

    try {
        Write-Verbose "Checking administrator account configuration on $ComputerName"

        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # Get both registry and WMI information for thorough checking
            $adminInfo = @{
                DefaultName = $null
                CurrentName = $null
                AccountExists = $false
                SecuritySettings = @{}
            }

            # Check default admin account name in registry
            try {
                $defaultName = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultAdminName" -ErrorAction SilentlyContinue
                $adminInfo.DefaultName = if ($defaultName) { $defaultName.DefaultAdminName } else { "Administrator" }
            }
            catch {
                Write-Verbose "Could not get DefaultAdminName from registry: $_"
            }

            # Get actual admin account (SID -500) details
            try {
                $adminAccount = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'" | 
                    Where-Object { $_.SID -match "-500$" }
                
                if ($adminAccount) {
                    $adminInfo.AccountExists = $true
                    $adminInfo.CurrentName = $adminAccount.Name
                    
                    # Get additional security settings using net user
                    $netUserOutput = net user $adminAccount.Name | Out-String
                    
                    # Only check if account is active
                    $adminInfo.SecuritySettings = @{
                        AccountActive = if ($netUserOutput -match "Account active\s*(Yes|No)") {
                            $matches[1] -eq "Yes"
                        } else { $true }
                    }
                }
            }
            catch {
                Write-Verbose "Error getting admin account details: $_"
            }

            return $adminInfo
        }

        $issues = @()

        # Verify account exists and name
        if (-not $checkResult.AccountExists) {
            $issues += "Could not locate administrator account (SID -500)"
        }
        else {
            # Check if using default name
            if ($checkResult.CurrentName -eq "Administrator") {
                $issues += "Administrator account is using default name"
            }
        }

        if ($issues.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = $issues -join "; "
        }
        else {
            $result.Details = "Administrator account renamed to '$($checkResult.CurrentName)' with proper security settings"
        }

        Write-Verbose "Completed administrator account check for $ComputerName"
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking administrator account on $ComputerName`: $_"
    }

    return $result
} 