function Check-AutoLogon {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    Write-Verbose "Checking automatic logon settings on $ComputerName..."
    
    $result = @{
        CheckNumber = 13
        Name = "Automatic Logon"
        Description = "Automatic logons must be disabled"
        Status = "OK"
        Details = "Automatic logon is disabled"
        Function = $MyInvocation.MyCommand.Name
    }
    
    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "Checking Winlogon registry settings"
            $winlogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            $autoLogonValue = Get-ItemProperty -Path $winlogonKey -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
            
            return @{
                Exists = ($null -ne $autoLogonValue)
                Value = if ($null -ne $autoLogonValue) { $autoLogonValue.AutoAdminLogon } else { $null }
            }
        }
        
        if ($checkResult.Exists -and $checkResult.Value -eq "1") {
            Write-Verbose "Automatic logon is enabled"
            $result.Status = "WARNING"
            $result.Details = "Automatic logon is enabled"
        } else {
            Write-Verbose "Automatic logon is disabled or not configured"
        }
    }
    catch {
        Write-Verbose "Error in Check-AutoLogon: $_"
        $result.Status = "WARNING"
        $result.Details = "Failed to check AutoLogon status: $_"
    }
    
    return $result
} 