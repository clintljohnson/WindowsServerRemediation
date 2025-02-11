function Check-CreateToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Checking Create Token Object user right assignment on $ComputerName..."
    
    $result = @{
        CheckNumber = 11
        Name = "Create Token Object User Right"
        Status = "OK"
        Details = "No unauthorized accounts have Create Token Object rights"
        Function = $MyInvocation.MyCommand.Name
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "Exporting security policy"
            $tempFile = [System.IO.Path]::GetTempFileName()
            
            try {
                secedit /export /cfg $tempFile /quiet
                $content = Get-Content $tempFile
                $line = $content | Where-Object { $_ -like "*SeCreateTokenPrivilege*" }
                
                $accounts = if ($line) {
                    ($line -split '=')[1].Trim() -split ','
                } else {
                    @()
                }
                
                return $accounts
            }
            finally {
                if (Test-Path $tempFile) {
                    Remove-Item $tempFile -Force
                }
            }
        }

        if ($checkResult.Count -gt 0) {
            Write-Verbose "Found accounts with Create Token Object rights: $($checkResult -join ', ')"
            $result.Status = "WARNING"
            $result.Details = "Accounts found with Create Token Object rights: $($checkResult -join ', ')"
        }
    }
    catch {
        Write-Verbose "Error in Check-CreateToken: $_"
        $result.Status = "WARNING"
        $result.Details = "Failed to check Create Token Object rights: $_"
    }

    return $result
} 