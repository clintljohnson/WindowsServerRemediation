function Check-DCERPCEndpoints {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 41
        Name = "DCE/RPC Endpoint Security Configuration"
        Status = "OK"
        Details = "DCE/RPC endpoint security is properly configured"
    }

    try {
        Write-Verbose "Checking DCE/RPC endpoint security configuration on $ComputerName"
        
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $issues = @()
            
            # Check RPC endpoint mapper security
            $rpcKey = "HKLM:\SOFTWARE\Microsoft\Rpc\Internet"
            if (Test-Path $rpcKey) {
                $portRanges = Get-ItemProperty -Path $rpcKey -Name "Ports" -ErrorAction SilentlyContinue
                $useInternetPorts = Get-ItemProperty -Path $rpcKey -Name "UseInternetPorts" -ErrorAction SilentlyContinue
                
                if (-not $portRanges -or -not $useInternetPorts) {
                    $issues += "RPC port ranges not properly configured"
                }
            } else {
                $issues += "RPC Internet configuration key missing"
            }

            # Check RPC authentication level
            $authLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Rpc" -Name "AuthenticationLevel" -ErrorAction SilentlyContinue
            if (-not $authLevel -or $authLevel.AuthenticationLevel -lt 6) {
                $issues += "RPC authentication level not set to Privacy/Encryption (6)"
            }

            # Check RPC security callback configuration
            $rpcRestrictKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
            $restrictRemoteClients = Get-ItemProperty -Path $rpcRestrictKey -Name "RestrictRemoteClients" -ErrorAction SilentlyContinue
            if (-not $restrictRemoteClients -or $restrictRemoteClients.RestrictRemoteClients -ne 1) {
                $issues += "RPC remote client restrictions not properly configured"
            }

            return @{
                Issues = $issues
                HasIssues = $issues.Count -gt 0
            }
        }

        if ($checkResult.HasIssues) {
            $result.Status = "WARNING"
            $result.Details = "DCE/RPC endpoint security issues found: $($checkResult.Issues -join '; ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking DCE/RPC endpoint security: $_"
    }

    return $result
} 