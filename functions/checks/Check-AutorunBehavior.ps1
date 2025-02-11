function Check-AutorunBehavior {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Checking default autorun behavior on $ComputerName..."

    $result = @{
        CheckNumber = 5
        Name = "Default Autorun Behavior"
        Status = "OK"
        Details = "Autorun commands are properly restricted"
        Function = $MyInvocation.MyCommand.Name
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "Checking Explorer policies registry key"
            $autorunKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            $autorunValue = Get-ItemProperty -Path $autorunKey -Name "NoAutorun" -ErrorAction SilentlyContinue
            
            return @{
                Exists = ($null -ne $autorunValue)
                Value = if ($null -ne $autorunValue) { $autorunValue.NoAutorun } else { $null }
            }
        }

        if (-not $checkResult.Exists -or $checkResult.Value -ne 1) {
            Write-Verbose "Autorun commands are not properly restricted"
            $result.Status = "WARNING"
            $result.Details = "Autorun commands are not properly restricted"
        }
    }
    catch {
        Write-Verbose "Error in Check-AutorunBehavior: $_"
        $result.Status = "WARNING"
        $result.Details = "Failed to check autorun behavior: $_"
    }

    return $result
} 