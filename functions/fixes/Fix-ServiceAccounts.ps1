function Fix-ServiceAccounts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for Service Account permissions on $ComputerName"

    try {
        # First get the current state
        $currentState = Check-ServiceAccounts -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $services = Get-WmiObject -Class Win32_Service | 
                Where-Object { $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY|NT Service)' }

            $fixed = @()
            $failed = @()

            foreach ($service in $services) {
                $account = $service.StartName
                
                try {
                    # 1. Remove excessive permissions
                    $adminGroups = @(
                        "Administrators",
                        "Domain Admins",
                        "Enterprise Admins",
                        "Schema Admins"
                    )
                    
                    foreach ($group in $adminGroups) {
                        $groupMembers = net localgroup $group 2>$null
                        if ($groupMembers -match [regex]::Escape($account)) {
                            $removeResult = net localgroup $group $account /delete 2>&1
                            if ($LASTEXITCODE -eq 0) {
                                $fixed += "Removed '$account' from group '$group'"
                            }
                            else {
                                $failed += "Failed to remove '$account' from group '$group': $removeResult"
                            }
                        }
                    }

                    # 2. Grant minimum required permissions
                    # Add "Log on as a service" right
                    $ntrights = "$env:SystemRoot\System32\ntrights.exe"
                    if (Test-Path $ntrights) {
                        $addRight = & $ntrights -u $account +r SeServiceLogonRight 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            $fixed += "Granted 'Log on as a service' right to '$account'"
                        }
                        else {
                            $failed += "Failed to grant 'Log on as a service' right: $addRight"
                        }
                    }
                    else {
                        $failed += "ntrights.exe not found - cannot modify user rights"
                    }

                    # Grant minimum folder permissions
                    $servicePath = $service.PathName -replace '^"|"$' -replace '".*$'
                    if ($servicePath -and (Test-Path $servicePath)) {
                        $serviceFolder = Split-Path -Parent $servicePath
                        try {
                            $acl = Get-Acl $serviceFolder
                            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                                $account,
                                "ReadAndExecute",
                                "ContainerInherit,ObjectInherit",
                                "None",
                                "Allow"
                            )
                            $acl.AddAccessRule($rule)
                            Set-Acl -Path $serviceFolder -AclObject $acl
                            $fixed += "Granted ReadAndExecute permissions to '$account' on '$serviceFolder'"
                        }
                        catch {
                            $failed += "Failed to set folder permissions: $_"
                        }
                    }
                }
                catch {
                    $failed += "Error processing service account '$account': $_"
                }
            }

            return @{
                Fixed = $fixed
                Failed = $failed
                Success = $failed.Count -eq 0
            }
        }

        if ($result.Success) {
            foreach ($fix in $result.Fixed) {
                Write-Host "Fixed: $fix" -ForegroundColor Green
            }
            
            # Verify the fix
            $verifyResult = Check-ServiceAccounts -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        else {
            foreach ($error in $result.Failed) {
                Write-Warning $error
            }
            return $false
        }
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 