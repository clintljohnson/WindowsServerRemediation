function Check-OperatingSystemRight {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 2
        Name = "Operating System Right Assignment"
        Status = "OK"
        Details = "Only authorized accounts have 'Act as part of the operating system' right"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $tempFile = [System.IO.Path]::GetTempFileName()
            
            try {
                # Export security policy to temp file
                secedit /export /cfg $tempFile /quiet
                
                # Read the content and find SeTcbPrivilege
                $content = Get-Content $tempFile
                $line = $content | Where-Object { $_ -like "*SeTcbPrivilege*" }
                
                if ($line) {
                    # Extract accounts
                    $accounts = ($line -split '=')[1].Trim() -split ','
                    
                    # Return unauthorized accounts (anything not Local System)
                    $accounts | Where-Object { $_ -ne "*S-1-5-18" -and $_ -ne "" }
                }
            }
            finally {
                # Clean up temp file
                if (Test-Path $tempFile) {
                    Remove-Item $tempFile -Force
                }
            }
        }

        if ($checkResult.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = "Unauthorized accounts have 'Act as part of the operating system' right: $($checkResult -join ', ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking operating system right: $_"
    }

    return $result
} 