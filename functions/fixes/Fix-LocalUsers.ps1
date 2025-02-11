function Fix-LocalUsers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for LocalUsers on $ComputerName"

    try {
        $currentState = Check-LocalUsers -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        $netUserOutput = Invoke-Command -ComputerName $ComputerName -ScriptBlock { 
            $adminSID = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'" | 
                Where-Object { $_.SID -match "-500$" }

            $builtInAccounts = @(
                $adminSID.Name,
                'Administrator',
                'Guest',
                'DefaultAccount',
                'WDAGUtilityAccount'
            )

            $users = net user
            $userList = $users | 
                Select-Object -Skip 4 | 
                Select-Object -SkipLast 2 | 
                ForEach-Object { $_.Trim() -split '\s+' } |
                Where-Object { $_ -and $_ -notin $builtInAccounts }
            
            return $userList
        }

        $modified = $false
        foreach ($user in $netUserOutput) {
            Write-Host "Found unauthorized local user: $user"
            $action = Read-Host "Choose action for user '$user': (D)isable, (R)emove, or (S)kip [S]"
            
            $result = switch ($action.ToUpper()) {
                'D' {
                    Write-Verbose "Disabling user: $user"
                    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                        param($username)
                        net user $username /active:no
                    } -ArgumentList $user
                    Write-Host "Disabled user account: $user" -ForegroundColor Green
                    $modified = $true
                }
                'R' {
                    Write-Verbose "Removing user: $user"
                    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                        param($username)
                        net user $username /delete
                    } -ArgumentList $user
                    Write-Host "Removed user account: $user" -ForegroundColor Green
                    $modified = $true
                }
                Default {
                    Write-Verbose "Skipped user: $user"
                    Write-Host "Skipped user account: $user" -ForegroundColor Yellow
                }
            }
        }

        if ($modified) {
            $verifyResult = Check-LocalUsers -ComputerName $ComputerName
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            } else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to fix local users: $_"
        return $false
    }
} 