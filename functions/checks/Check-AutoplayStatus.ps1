function Check-AutoplayStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    Write-Verbose "Checking Autoplay status for all drives on $ComputerName..."
    
    $result = @{
        CheckNumber = 7
        Name = "Autoplay Status"
        Description = "Autoplay should be disabled for all drives"
        Status = "OK"
        Details = "Autoplay is disabled for all drives"
        Function = $MyInvocation.MyCommand.Name
    }
    
    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "Checking Explorer policies registry key"
            $autoplayKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            $autoplayValue = Get-ItemProperty -Path $autoplayKey -Name "NoDriveTypeAutoRun" # -ErrorAction SilentlyContinue
            
            return @{
                Exists = ($null -ne $autoplayValue)
                Value = if ($null -ne $autoplayValue) { $autoplayValue.NoDriveTypeAutoRun } else { $null }
            }
        }
        
        if (-not $checkResult.Exists -or $checkResult.Value -ne 255) {
            Write-Verbose "Autoplay is not properly disabled"
            $result.Status = "WARNING"
            $result.Details = "Autoplay is not disabled for all drives"
        }
    }
    catch {
        Write-Verbose "Error in Check-AutoplayStatus: $_"
        $result.Status = "WARNING"
        $result.Details = "Failed to check Autoplay status: $_"
    }
    
    return $result
} 