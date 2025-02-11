function Check-AnonymousPipes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Checking anonymous pipe access settings on $ComputerName"

    $result = @{
        CheckNumber = 6
        Name = "Anonymous Named Pipes Access"
        Status = "OK"
        Details = "No anonymous pipe access configured (default secure setting)"
        Function = $MyInvocation.MyCommand.Name
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "Checking registry for anonymous pipe settings"
            # Registry path for anonymous pipe access
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            $regName = "NullSessionPipes"

            # Get the current setting
            $pipes = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
            
            if ($null -eq $pipes) {
                return @{ Exists = $false }
            }

            return @{
                Exists = $true
                Values = $pipes.NullSessionPipes
            }
        }

        if (-not $checkResult.Exists) {
            Write-Verbose "No anonymous pipe settings found (secure default)"
            return $result
        }

        $pipeValues = $checkResult.Values
        if ($pipeValues.Count -eq 0 -or ($pipeValues.Count -eq 1 -and [string]::IsNullOrEmpty($pipeValues[0]))) {
            Write-Verbose "Anonymous pipe access is properly restricted"
        } else {
            Write-Verbose "Found configured anonymous pipes: $($pipeValues -join ', ')"
            $result.Status = "WARNING"
            $result.Details = "Anonymous pipe access allowed for: $($pipeValues -join ', ')"
        }
    }
    catch {
        Write-Verbose "Error in Check-AnonymousPipes: $_"
        $result.Status = "WARNING"
        $result.Details = "Error checking anonymous pipe access: $_"
    }

    return $result
}