function Check-ServiceAccounts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 40
        Name = "Service Account Permissions"
        Status = "OK"
        Details = "Service accounts have appropriate minimum permissions"
    }

    try {
        Write-Verbose "Starting service account permissions check on $ComputerName"
        
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # Get all services and their accounts, excluding Windows user services and built-in accounts
            Write-Verbose "Retrieving service list..."
            $services = Get-WmiObject -Class Win32_Service | 
                Where-Object { 
                    $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY|NT Service)' -and
                    $_.Name -notmatch '_[a-f0-9]{6}$' -and
                    ![string]::IsNullOrWhiteSpace($_.StartName)
                }

            Write-Verbose "Found $($services.Count) services to check"
            $issues = @()
            
            foreach ($service in $services) {
                $account = $service.StartName
                $serviceIssues = @()
                
                try {
                    Write-Verbose "`nChecking service '$($service.DisplayName)' with account '$account'"
                    
                    # 1. Check for administrative privileges
                    $adminGroups = @(
                        "Administrators",
                        "Domain Admins",
                        "Enterprise Admins",
                        "Schema Admins"
                    )
                    
                    foreach ($group in $adminGroups) {
                        $groupMembers = net localgroup $group 2>$null
                        if ($groupMembers -match [regex]::Escape($account)) {
                            $serviceIssues += "Member of $group"
                        }
                    }

                    # 2. Check required permissions
                    $requiredPermissions = @{
                        "Log on as a service" = $false
                        "Log on as a batch job" = $false
                    }

                    $userRights = secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
                    $secpol = Get-Content "$env:TEMP\secpol.cfg"
                    Remove-Item "$env:TEMP\secpol.cfg" -Force

                    # Check permissions
                    if ($secpol | Where-Object { $_ -match "SeServiceLogonRight" } -match [regex]::Escape($account)) {
                        $requiredPermissions["Log on as a service"] = $true
                    }
                    if ($secpol | Where-Object { $_ -match "SeBatchLogonRight" } -match [regex]::Escape($account)) {
                        $requiredPermissions["Log on as a batch job"] = $true
                    }

                    # Check folder permissions
                    $servicePath = $service.PathName -replace '^"|"$' -replace '".*$'
                    if ($servicePath -and (Test-Path $servicePath)) {
                        $serviceFolder = Split-Path -Parent $servicePath
                        $acl = Get-Acl $serviceFolder
                        $hasReadExecute = $false
                        
                        foreach ($ace in $acl.Access) {
                            if ($ace.IdentityReference.Value -eq $account) {
                                if (($ace.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadAndExecute) -eq [System.Security.AccessControl.FileSystemRights]::ReadAndExecute) {
                                    $hasReadExecute = $true
                                    break
                                }
                            }
                        }

                        if (-not $hasReadExecute) {
                            $serviceIssues += "Lacks ReadAndExecute permissions on service directory"
                        }
                    }

                    # Check for missing permissions
                    foreach ($perm in $requiredPermissions.Keys) {
                        if (-not $requiredPermissions[$perm]) {
                            $serviceIssues += "Missing permission: $perm"
                        }
                    }

                    # Output verbose status for this service
                    if ($serviceIssues.Count -gt 0) {
                        Write-Verbose "  [WARNING] Issues found:"
                        foreach ($issue in $serviceIssues) {
                            Write-Verbose "    - $issue"
                        }
                        $issues += "Service '$($service.DisplayName)' account '$account': $($serviceIssues -join ', ')"
                    } else {
                        Write-Verbose "  [OK] Service account permissions are compliant"
                    }
                }
                catch {
                    Write-Verbose "  [ERROR] Failed to check service: $_"
                    $issues += "Error checking permissions for service '$($service.DisplayName)': $_"
                }
            }

            return @{
                HasIssues = $issues.Count -gt 0
                Issues = $issues
            }
        }

        if ($checkResult.HasIssues) {
            $result.Status = "WARNING"
            $result.Details = "Found service account permission issues:`n" + 
                ($checkResult.Issues | ForEach-Object { "- $_" } | Out-String).TrimEnd()
        }
        
        Write-Verbose "`nService account check completed with status: $($result.Status)"
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error performing check: $_"
        Write-Verbose "Check failed with error: $_"
    }

    return $result
} 