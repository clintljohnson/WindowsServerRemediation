function Check-AdminShares {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 39
        Name = "Default Administrative Shares"
        Status = "OK"
        Details = "ADMIN$ and C$ have been properly removed, IPC$ must remain for interprocess communications"
    }

    try {
        Write-Verbose "Checking administrative shares on $ComputerName"
        
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $adminShares = @('ADMIN$', 'C$')
            $foundShares = @()
            
            # Use WMI to check for shares instead of net share command
            $shares = Get-WmiObject -Class Win32_Share
            foreach ($share in $shares) {
                if ($share.Name -in $adminShares) {
                    $foundShares += $share.Name
                }
            }
            
            return @{
                FoundShares = $foundShares
            }
        }

        if ($checkResult.FoundShares.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = "Found active administrative shares: $($checkResult.FoundShares -join ', ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking administrative shares: $_"
    }

    return $result
}
