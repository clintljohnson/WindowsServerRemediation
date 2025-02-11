function Check-GuestAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    Write-Verbose "Checking Guest account status on $ComputerName..."
    
    $result = @{
        CheckNumber = 19
        Name = "Guest Account Status"
        Status = "OK"
        Details = "Guest account is disabled"
        Function = $MyInvocation.MyCommand.Name
    }
    
    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "Retrieving Guest account status"
            
            # Check using multiple methods for reliability
            $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
            
            if ($null -eq $guestAccount) {
                # Fallback to net user if Get-LocalUser fails
                $netUserOutput = net user Guest 2>&1
                $accountExists = $netUserOutput -notmatch "The user name could not be found"
                $accountEnabled = $accountExists -and ($netUserOutput -match "Account active\s+Yes")
                
                return @{
                    Exists = $accountExists
                    Enabled = $accountEnabled
                }
            }
            
            return @{
                Exists = $true
                Enabled = $guestAccount.Enabled
            }
        }
        
        if ($checkResult.Exists) {
            if ($checkResult.Enabled) {
                Write-Verbose "Guest account is enabled on $ComputerName"
                $result.Status = "WARNING"
                $result.Details = "Guest account is enabled and should be disabled"
            } else {
                Write-Verbose "Guest account is properly disabled on $ComputerName"
            }
        } else {
            Write-Verbose "Guest account not found on $ComputerName"
        }
    }
    catch {
        Write-Verbose "Error checking Guest account: $_"
        $result.Status = "WARNING"
        $result.Details = "Failed to check Guest account status: $_"
    }
    
    return $result
} 