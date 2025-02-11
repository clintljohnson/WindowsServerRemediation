function Fix-DCERPCEndpoints {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$false)]
        [switch]$NoRestart
    )

    Write-Warning "This fix will modify RPC security settings and requires a RPC service restart."
    Write-Warning "The RPC restart will temporarily disconnect remote sessions and may affect running services."
    
    $confirmation = Read-Host "Are you sure you want to continue? (y/N)"
    if ($confirmation -ne 'y') {
        Write-Host "Fix cancelled by user"
        return $false
    }

    Write-Verbose "Starting fix operation for DCE/RPC endpoint security on $ComputerName"

    try {
        # First check current state
        $currentState = Check-DCERPCEndpoints -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        # Send all configuration commands in a single remote session
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $success = $true
            $messages = @()

            try {
                # Configure RPC endpoint mapper security
                $rpcKey = "HKLM:\SOFTWARE\Microsoft\Rpc\Internet"
                if (-not (Test-Path $rpcKey)) {
                    $parentKey = Split-Path $rpcKey -Parent
                    if (-not (Test-Path $parentKey)) {
                        New-Item -Path $parentKey -Force | Out-Null
                        $messages += "Created parent RPC key"
                    }
                    New-Item -Path $rpcKey -Force | Out-Null
                    $messages += "Created RPC Internet key"
                }

                # Set restricted port range
                Set-ItemProperty -Path $rpcKey -Name "Ports" -Value "49152-65535" -Type String
                Set-ItemProperty -Path $rpcKey -Name "UseInternetPorts" -Value 1 -Type DWord
                $messages += "Configured RPC port ranges"

                # Set RPC authentication level
                $rpcNTKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Rpc"
                if (-not (Test-Path $rpcNTKey)) {
                    New-Item -Path $rpcNTKey -Force | Out-Null
                    $messages += "Created RPC NT key"
                }
                Set-ItemProperty -Path $rpcNTKey -Name "AuthenticationLevel" -Value 6 -Type DWord
                $messages += "Set RPC authentication level to Privacy"

                # Configure RPC security callback restrictions
                $rpcRestrictKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
                if (-not (Test-Path $rpcRestrictKey)) {
                    New-Item -Path $rpcRestrictKey -Force | Out-Null
                }
                Set-ItemProperty -Path $rpcRestrictKey -Name "RestrictRemoteClients" -Value 1 -Type DWord
                $messages += "Configured RPC remote client restrictions"

                if ($using:NoRestart) {
                    $messages += "Skipping service restart (NoRestart specified)"
                } else {
                    # Schedule the service restarts with a delay
                    $restartScript = {
                        Start-Sleep -Seconds 2
                        Stop-Service RpcSs -Force
                        Start-Sleep -Seconds 2
                        Start-Service RpcSs
                        Start-Sleep -Seconds 2
                        Stop-Service WinRM -Force
                        Start-Sleep -Seconds 2
                        Start-Service WinRM
                    }
                    
                    # Start the restart script in a separate process so it continues even if we disconnect
                    Start-Process powershell -ArgumentList "-Command & {$restartScript}" -WindowStyle Hidden
                    $messages += "Scheduled service restarts"
                }

                return @{
                    Success = $success
                    Messages = $messages
                }
            }
            catch {
                return @{
                    Success = $false
                    Messages = @("Error during fix: $_")
                }
            }
        }

        if ($result.Success) {
            Write-Host "Successfully applied DCE/RPC endpoint security fixes:" -ForegroundColor Green
            $result.Messages | ForEach-Object { Write-Host "- $_" }
            
            # Wait for services to restart and stabilize
            Write-Host "Waiting 30 seconds for services to restart and stabilize..."
            Start-Sleep -Seconds 30

            # Verify the fix
            Write-Host "Verifying configuration..."
            $verifyResult = Check-DCERPCEndpoints -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Host "Fix successfully applied and verified" -ForegroundColor Green
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply DCE/RPC endpoint security fixes"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 