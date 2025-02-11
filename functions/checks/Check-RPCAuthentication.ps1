function Check-RPCAuthentication {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 38
        Name = "RPC Authentication Security"
        Status = "OK"
        Details = "RPC authentication settings are properly configured"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # Check registry settings for RPC authentication
            $rpcAuthPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
            $rpcAuthSettings = @{
                "RestrictRemoteClients" = 1  # Require authentication
                "EnableAuthEpResolution" = 1 # Enable authenticated endpoint resolution
            }

            $issues = @()

            # Check if the RPC policy key exists
            if (-not (Test-Path $rpcAuthPath)) {
                $issues += "RPC policy registry key not found"
            } else {
                foreach ($setting in $rpcAuthSettings.GetEnumerator()) {
                    $value = Get-ItemProperty -Path $rpcAuthPath -Name $setting.Key -ErrorAction SilentlyContinue
                    if ($null -eq $value -or $value.$($setting.Key) -ne $setting.Value) {
                        $issues += "RPC $($setting.Key) is not set to secure value $($setting.Value)"
                    }
                }
            }

            # Check if anonymous RPC is restricted
            $anonRpcPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $restrictAnonymous = (Get-ItemProperty -Path $anonRpcPath -Name "RestrictAnonymous" -ErrorAction SilentlyContinue).RestrictAnonymous
            if ($null -eq $restrictAnonymous -or $restrictAnonymous -ne 1) {
                $issues += "Anonymous RPC access is not properly restricted"
            }

            return @{
                Issues = $issues
                RestrictAnonymous = $restrictAnonymous
            }
        }

        if ($checkResult.Issues.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = "RPC security issues found: $($checkResult.Issues -join '; ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error performing RPC authentication check: $_"
    }

    return $result
} 