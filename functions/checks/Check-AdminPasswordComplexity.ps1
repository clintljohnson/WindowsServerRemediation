function Check-AdminPasswordComplexity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting Check-AdminPasswordComplexity for $ComputerName"

    $result = @{
        CheckNumber = 16
        Name = "Administrator Password Complexity"
        Status = "OK"
        Details = "Administrator password meets complexity requirements"
    }

    try {
        Write-Verbose "Checking administrator password complexity settings on $ComputerName"
        
        # Test if we can connect to the computer
        if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
            throw "Cannot connect to $ComputerName"
        }

        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "Starting remote check on $env:COMPUTERNAME"

            # Get Administrator SID and account details
            $adminAccount = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'" | 
                Where-Object { $_.SID -match "-500$" }
            
            if (-not $adminAccount) {
                throw "Could not find Administrator account"
            }

            Write-Verbose "Found Administrator account: $($adminAccount.Name)"

            # Get password expiration info using ADSI
            try {
                $computer = [ADSI]"WinNT://$env:COMPUTERNAME"
                $user = $computer.Children | Where-Object { $_.SchemaClassName -eq 'user' -and $_.Name -eq $adminAccount.Name }
                
                if (-not $user) {
                    throw "Could not find Administrator account using ADSI"
                }

                Write-Verbose "Successfully retrieved ADSI user object"

                # Get both security policy and current admin account settings
                $securityPolicy = @{}
                $policyOutput = secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet
                if (Test-Path "$env:TEMP\secpol.cfg") {
                    try {
                        $policyContent = Get-Content "$env:TEMP\secpol.cfg" -Raw
                        
                        # Parse complexity requirements
                        if ($policyContent -match 'PasswordComplexity\s*=\s*(\d+)') {
                            $securityPolicy['ComplexityEnabled'] = $matches[1] -eq '1'
                        }
                        if ($policyContent -match 'MinimumPasswordLength\s*=\s*(\d+)') {
                            $securityPolicy['MinLength'] = [int]$matches[1]
                        }
                        if ($policyContent -match 'PasswordHistorySize\s*=\s*(\d+)') {
                            $securityPolicy['HistorySize'] = [int]$matches[1]
                        }
                    }
                    finally {
                        Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue
                    }
                }

                # Get user flags to check "never expires" status
                $userFlags = $user.UserFlags.Value
                $neverExpires = ($userFlags -band 65536) -eq 65536

                # Get maximum password age from security policy
                $maxAge = if ($policyContent -match 'MaximumPasswordAge\s*=\s*(\d+)') {
                    [int]$matches[1]
                } else {
                    364 # default
                }

                # Get password last set date
                try {
                    if ($user.PasswordAge -eq $null) {
                        Write-Verbose "PasswordAge property is null, using alternate method"
                        # Try using WMI first
                        $userWMI = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' AND SID LIKE '%-500'"
                        if ($userWMI.PasswordLastChanged) {
                            $lastSet = $userWMI.PasswordLastChanged
                            Write-Verbose "Password last set date from WMI: $lastSet"
                        } else {
                            # Try using net user command as fallback
                            $netUserOutput = net user $adminAccount.Name | Out-String
                            if ($netUserOutput -match "Password last set\s*([\d/]+)") {
                                $lastSet = [datetime]::Parse($matches[1])
                                Write-Verbose "Password last set date from net user: $lastSet"
                            } else {
                                $lastSet = Get-Date # Use current date as final fallback
                                Write-Verbose "Using current date as fallback: $lastSet"
                            }
                        }
                    } else {
                        $lastSet = [datetime]::FromFileTime($user.PasswordAge.Value)
                        Write-Verbose "Password last set date from ADSI: $lastSet"
                        
                        # Validate the date
                        if ($lastSet.Year -lt 1970 -or $lastSet.Year -gt ([datetime]::Now.Year + 1)) {
                            Write-Verbose "Invalid date detected, using alternate method"
                            $userWMI = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' AND SID LIKE '%-500'"
                            $lastSet = if ($userWMI.PasswordLastChanged) {
                                $userWMI.PasswordLastChanged
                            } else {
                                Get-Date
                            }
                            Write-Verbose "Password last set date from WMI: $lastSet"
                        }
                    }
                }
                catch {
                    Write-Verbose "Error getting password age: $_"
                    $lastSet = Get-Date # Use current date as fallback
                    Write-Verbose "Using fallback date: $lastSet"
                }

                Write-Verbose "Final last set date: $lastSet"
                Write-Verbose "Maximum password age: $maxAge days"
                Write-Verbose "Never expires flag: $neverExpires"

                $expirationDate = if (-not $neverExpires) {
                    $expDate = $lastSet.AddDays($maxAge)
                    Write-Verbose "Calculated expiration date: $expDate"
                    $expDate
                } else {
                    Write-Verbose "Password set to never expire"
                    $null
                }

                return @{
                    Policy = $securityPolicy
                    AdminAccount = @{
                        Name = $adminAccount.Name
                        PasswordLastSet = $lastSet
                        PasswordNeverExpires = $neverExpires
                        ExpirationDate = $expirationDate
                    }
                }
            }
            catch {
                Write-Verbose "Error getting password expiration info: $_"
                return @{
                    Policy = @{}
                    AdminAccount = @{
                        Name = $adminAccount.Name
                        PasswordLastSet = $null
                        PasswordNeverExpires = $false
                        ExpirationDate = $null
                    }
                }
            }
        }

        $issues = @()

        # Check policy requirements
        if (-not $checkResult.Policy.ComplexityEnabled) {
            $issues += "Password complexity is not enabled"
        }
        if ($checkResult.Policy.MinLength -lt 14) {
            $issues += "Minimum password length ($($checkResult.Policy.MinLength)) is less than required (14)"
        }
        if ($checkResult.Policy.HistorySize -lt 24) {
            $issues += "Password history size ($($checkResult.Policy.HistorySize)) is less than required (24)"
        }

        # Check password expiration
        if ($checkResult.AdminAccount.PasswordNeverExpires) {
            Write-Verbose "Account configured to never expire"
            $issues += "Administrator password is set to never expire"
        }
        elseif ($checkResult.AdminAccount.ExpirationDate) {
            Write-Verbose "Last set: $($checkResult.AdminAccount.PasswordLastSet)"
            Write-Verbose "Expires: $($checkResult.AdminAccount.ExpirationDate)"
            $daysUntilExpiry = [math]::Round(($checkResult.AdminAccount.ExpirationDate - (Get-Date)).TotalDays)
            Write-Verbose "Days until expiry calculation: ($($checkResult.AdminAccount.ExpirationDate) - $(Get-Date)) = $daysUntilExpiry days"
            
            if ($daysUntilExpiry -gt 364) {
                $issues += "Administrator password expiration is set beyond 364 days"
            }
        }

        # Process results
        if ($issues.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = $issues -join "; "
        }
        else {
            $daysUntilExpiration = if ($checkResult.AdminAccount.ExpirationDate) {
                Write-Verbose "Calculating days until expiration:"
                Write-Verbose "  Expiration date: $($checkResult.AdminAccount.ExpirationDate)"
                Write-Verbose "  Current date: $(Get-Date)"
                $days = [math]::Round(($checkResult.AdminAccount.ExpirationDate - (Get-Date)).TotalDays)
                Write-Verbose "  Days until expiration: $days"
                $days
            } else {
                Write-Verbose "No expiration date set, using 'never'"
                "never"
            }

            $result.Details = "Complexity enabled, min length $($checkResult.Policy.MinLength), " + 
                            "history size $($checkResult.Policy.HistorySize), " +
                            "expires in $daysUntilExpiration days"
        }

        Write-Verbose "Completed password complexity check for $ComputerName"
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking administrator password complexity on $ComputerName`: $_"
    }

    return $result
} 