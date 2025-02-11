function Check-DebugPrograms {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Checking Debug Programs user right assignment on $ComputerName..."
    
    $result = @{
        CheckNumber = 10
        Name = "Debug Programs User Right"
        Status = "OK"
        Details = "No unauthorized accounts have Debug Programs rights"
        Function = $MyInvocation.MyCommand.Name
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "Exporting security policy"
            $tempFile = [System.IO.Path]::GetTempFileName()
            
            try {
                secedit /export /cfg $tempFile /quiet
                $content = Get-Content $tempFile
                $line = $content | Where-Object { $_ -like "*SeDebugPrivilege*" }
                
                # Define allowed accounts (typically just local Administrators)
                $allowedAccounts = @("*\Administrators", "*S-1-5-32-544")  # Allow both friendly name and SID
                
                $accounts = if ($line) {
                    $rawAccounts = ($line -split '=')[1].Trim() -split ','
                    # Return both SID and friendly name for verification
                    $rawAccounts | ForEach-Object {
                        $account = $_.Trim()
                        $friendlyName = $null
                        
                        if ($account -match '^(\*S-1-5-[\d-]+)$') {
                            try {
                                $sid = New-Object System.Security.Principal.SecurityIdentifier($account.TrimStart('*'))
                                $friendlyName = $sid.Translate([System.Security.Principal.NTAccount]).Value
                            } catch {
                                $friendlyName = $account
                            }
                        }
                        
                        @{
                            OriginalValue = $account
                            FriendlyName = $friendlyName
                        }
                    }
                } else {
                    @()
                }
                
                return @{
                    AllAccounts = $accounts
                    AllowedAccounts = $allowedAccounts
                }
            }
            finally {
                if (Test-Path $tempFile) {
                    Remove-Item $tempFile -Force
                }
            }
        }

        # Format all current accounts for display
        $currentAccounts = $checkResult.AllAccounts | ForEach-Object {
            if ($_.FriendlyName) { $_.FriendlyName } else { $_.OriginalValue }
        }
        
        # Check for unauthorized accounts
        $unauthorizedAccounts = $checkResult.AllAccounts | Where-Object {
            $account = $_
            -not ($checkResult.AllowedAccounts | Where-Object { 
                $account.OriginalValue -like $_ -or $account.FriendlyName -like $_
            })
        }

        if ($unauthorizedAccounts) {
            $friendlyOutput = $unauthorizedAccounts | ForEach-Object {
                if ($_.FriendlyName) { $_.FriendlyName } else { $_.OriginalValue }
            }
            Write-Verbose "Found unauthorized accounts with Debug Programs rights: $($friendlyOutput -join ', ')"
            $result.Status = "WARNING"
            $result.Details = "Unauthorized accounts have Debug Programs rights: $($friendlyOutput -join ', ')"
        } else {
            $result.Details = "Current accounts with Debug Programs rights: $($currentAccounts -join ', ')"
        }
    }
    catch {
        Write-Verbose "Error in Check-DebugPrograms: $_"
        $result.Status = "WARNING"
        $result.Details = "Failed to check Debug Programs rights: $_"
    }

    return $result
} 