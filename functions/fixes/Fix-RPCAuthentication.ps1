function Fix-RPCAuthentication {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for RPC Authentication on $ComputerName"

    try {
        # First verify current state
        $currentState = Check-RPCAuthentication -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - RPC authentication settings are already compliant"
            return $true
        }

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $rpcAuthPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
            $anonRpcPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            
            try {
                # Create RPC policy key if it doesn't exist
                if (-not (Test-Path $rpcAuthPath)) {
                    Write-Verbose "Creating RPC policy registry key"
                    New-Item -Path $rpcAuthPath -Force | Out-Null
                }

                # Configure RPC authentication settings
                Write-Verbose "Setting RestrictRemoteClients to 1"
                Set-ItemProperty -Path $rpcAuthPath -Name "RestrictRemoteClients" -Value 1 -Type DWord -Force

                Write-Verbose "Setting EnableAuthEpResolution to 1"
                Set-ItemProperty -Path $rpcAuthPath -Name "EnableAuthEpResolution" -Value 1 -Type DWord -Force

                # Restrict anonymous RPC access
                Write-Verbose "Setting RestrictAnonymous to 1"
                Set-ItemProperty -Path $anonRpcPath -Name "RestrictAnonymous" -Value 1 -Type DWord -Force

                return $true
            }
            catch {
                Write-Error "Failed to apply RPC authentication fixes: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully applied RPC authentication fixes" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-RPCAuthentication -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "RPC authentication fix verification passed"
                return $true
            }
            else {
                Write-Warning "RPC authentication fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply RPC authentication fixes"
        return $false
    }
    catch {
        Write-Error "Error in RPC authentication fix operation: $_"
        return $false
    }
} 