function Check-LocalUsers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 20
        Name = "Local Users Check"
        Status = "OK"
        Details = "No unauthorized local users found"
    }

    try {
        Write-Verbose "Checking local users on $ComputerName"

        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # Get all users and their status
            $users = net user
            $userDetails = @{}
            
            # Get renamed Administrator account by SID
            $adminAccount = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'" | 
                Where-Object { $_.SID -match "-500$" }
            
            # Define built-in accounts to exclude
            $builtInAccounts = @(
                $adminAccount.Name,
                'Administrator',
                'Guest',
                'DefaultAccount',
                'WDAGUtilityAccount'
            )
            
            # Process user list
            $users | Select-Object -Skip 4 | Select-Object -SkipLast 2 | 
                ForEach-Object { $_.Trim() -split '\s+' } | 
                Where-Object { $_ -and $_ -notin $builtInAccounts } | 
                ForEach-Object {
                    $userInfo = net user $_ | Select-String "Account active"
                    $isActive = $userInfo -match "Yes"
                    $userDetails[$_] = $isActive
                }
            
            return @{
                Users = $userDetails
                AdminAccount = $adminAccount.Name
            }
        }

        Write-Verbose "Administrator account name is: $($checkResult.AdminAccount)"
        
        # Categorize users
        $activeUsers = @($checkResult.Users.Keys | Where-Object { $checkResult.Users[$_] })
        $disabledUsers = @($checkResult.Users.Keys | Where-Object { -not $checkResult.Users[$_] })

        if ($activeUsers.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = "Found $($activeUsers.Count) active local user(s): $($activeUsers -join ', '). Member servers should minimize local user accounts."
        } 
        elseif ($disabledUsers.Count -gt 0) {
            $result.Status = "OK"
            $result.Details = "Unauthorized local users found but are disabled: $($disabledUsers -join ', ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking local users on $ComputerName`: $_"
    }

    return $result
} 