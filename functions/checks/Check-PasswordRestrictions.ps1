function Check-PasswordRestrictions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    Write-Verbose "Checking password restrictions and complexity settings on $ComputerName..."

    $result = @{
        CheckNumber = 25
        Name = "General Local Account Password Restrictions"
        Status = "OK"
        Details = "Password restrictions and complexity settings meet requirements"
        Function = $MyInvocation.MyCommand.Name
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # First check if computer is domain-joined
            $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
            $isDomainJoined = $computerSystem.PartOfDomain
            $domainName = $computerSystem.Domain

            Write-Verbose "Checking domain status..."
            Write-Verbose "Domain joined: $isDomainJoined"
            Write-Verbose "Domain name: $domainName"

            # Export and check security policy settings
            Write-Verbose "Exporting security policy settings"
            $tempFile = [System.IO.Path]::GetTempFileName()
            
            try {
                secedit /export /cfg $tempFile /quiet
                $content = Get-Content $tempFile
                Write-Verbose "Security policy content: $($content -join "`n")"
                
                # Parse all relevant settings
                $settings = @{
                    ComplexityEnabled = $false
                    MinPasswordLength = 0
                    PasswordHistorySize = 0
                    MaxPasswordAge = 0
                    IsDomainJoined = $isDomainJoined
                    DomainName = $domainName
                }
                
                foreach ($line in $content) {
                    switch -Regex ($line.Trim()) {
                        'PasswordComplexity\s*=\s*(\d+)' { 
                            $settings.ComplexityEnabled = $matches[1] -eq '1'
                            Write-Verbose "Found PasswordComplexity: $($settings.ComplexityEnabled)"
                        }
                        'MinimumPasswordLength\s*=\s*(\d+)' { 
                            $settings.MinPasswordLength = [int]$matches[1]
                            Write-Verbose "Found MinPasswordLength: $($settings.MinPasswordLength)"
                        }
                        'PasswordHistorySize\s*=\s*(\d+)' { 
                            $settings.PasswordHistorySize = [int]$matches[1]
                            Write-Verbose "Found PasswordHistorySize: $($settings.PasswordHistorySize)"
                        }
                        'MaximumPasswordAge\s*=\s*(\d+)' { 
                            $settings.MaxPasswordAge = [int]$matches[1]
                            Write-Verbose "Found MaxPasswordAge: $($settings.MaxPasswordAge)"
                        }
                    }
                }
                
                return $settings
            }
            finally {
                if (Test-Path $tempFile) {
                    Remove-Item $tempFile -Force
                }
            }
        }

        Write-Verbose "Current settings:"
        Write-Verbose "ComplexityEnabled: $($checkResult.ComplexityEnabled)"
        Write-Verbose "MinPasswordLength: $($checkResult.MinPasswordLength)"
        Write-Verbose "PasswordHistorySize: $($checkResult.PasswordHistorySize)"
        Write-Verbose "MaxPasswordAge: $($checkResult.MaxPasswordAge)"
        Write-Verbose "Domain joined: $($checkResult.IsDomainJoined)"
        Write-Verbose "Domain name: $($checkResult.DomainName)"

        # Collect all issues at once
        $allIssues = @()
        
        if (-not $checkResult.ComplexityEnabled) {
            $allIssues += "Password complexity is not enabled"
        }
        if ($checkResult.MinPasswordLength -ne 14) {
            $allIssues += "Minimum password length ($($checkResult.MinPasswordLength)) should be exactly 14 characters"
        }
        if ($checkResult.PasswordHistorySize -ne 24) {
            $allIssues += "Password history size ($($checkResult.PasswordHistorySize)) should be exactly 24"
        }
        if ($checkResult.MaxPasswordAge -ne 90) {
            $allIssues += "Maximum password age ($($checkResult.MaxPasswordAge)) should be exactly 90 days"
        }

        Write-Verbose "Found $($allIssues.Count) issues"
        foreach ($issue in $allIssues) {
            Write-Verbose "Issue: $issue"
        }

        if ($allIssues.Count -gt 0) {
            Write-Verbose "Found password restriction issues on $ComputerName"
            $result.Status = "WARNING"
            
            # Modify the warning message based on domain status
            if ($checkResult.IsDomainJoined) {
                $result.Details = "Domain-controlled password policy ($($checkResult.DomainName)): " + ($allIssues -join "; ") + 
                    " [Changes must be made via Domain Group Policy]"
            } else {
                $result.Details = $allIssues -join "; "
            }
        }
    }
    catch {
        Write-Verbose "Error checking password restrictions: $_"
        $result.Status = "WARNING"
        $result.Details = "Error checking password restrictions: $_"
    }

    return $result
} 