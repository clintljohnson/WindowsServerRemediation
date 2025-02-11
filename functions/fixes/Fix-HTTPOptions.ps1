function Fix-HTTPOptions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting HTTP OPTIONS method remediation on $ComputerName"

    try {
        # Check global configuration first
        $globalStatus = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Import-Module WebAdministration
            $config = Get-WebConfiguration "/system.webServer/security/requestFiltering/verbs" "MACHINE/WEBROOT/APPHOST"
            $optionsVerb = $config | 
                Select-Object -ExpandProperty Collection |
                Where-Object { $_.verb -eq "OPTIONS" }
            
            @{
                OptionsEnabled = if ($optionsVerb) { $optionsVerb.allowed } else { $true }
                HasExplicitConfig = [bool]$optionsVerb
            }
        }

        if ($globalStatus.OptionsEnabled -or -not $globalStatus.HasExplicitConfig) {
            Write-Host "`nGlobal IIS Configuration:" -ForegroundColor Cyan
            $statusMessage = if ($globalStatus.HasExplicitConfig) { 'explicitly allowed' } else { 'allowed by default' }
            Write-Host "  OPTIONS method is currently $statusMessage"
            Write-Host "Would you like to explicitly deny OPTIONS method globally? (y/N): " -ForegroundColor Yellow -NoNewline
            $response = Read-Host
            
            if ($response -eq 'y') {
                Write-Host "  Explicitly denying OPTIONS method globally..." -NoNewline
                
                $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    try {
                        # Remove any existing OPTIONS configuration first
                        $existingConfig = Get-WebConfiguration "/system.webServer/security/requestFiltering/verbs/add[@verb='OPTIONS']" "MACHINE/WEBROOT/APPHOST"
                        if ($existingConfig) {
                            Clear-WebConfiguration "/system.webServer/security/requestFiltering/verbs/add[@verb='OPTIONS']" "MACHINE/WEBROOT/APPHOST"
                        }

                        # Add explicit deny for OPTIONS
                        Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
                            -Filter "system.webServer/security/requestFiltering/verbs" `
                            -Name "." `
                            -Value @{verb='OPTIONS';allowed='false'}
                        
                        # Ensure WebDAV doesn't override our settings
                        Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
                            -Filter "system.webServer/security/requestFiltering/verbs" `
                            -Name "applyToWebDAV" `
                            -Value "false"
                        
                        return @{ Success = $true }
                    }
                    catch {
                        return @{
                            Success = $false
                            Error = $_.Exception.Message
                        }
                    }
                }
                
                if ($result.Success) {
                    Write-Host "Success!" -ForegroundColor Green
                }
                else {
                    Write-Host "Failed!" -ForegroundColor Red
                    Write-Host "  Error: $($result.Error)" -ForegroundColor Red
                }
            }
            else {
                Write-Host "  Skipped." -ForegroundColor Yellow
            }
        }

        # Get all websites that need OPTIONS disabled
        $websiteStatus = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Import-Module WebAdministration
            Get-Website | ForEach-Object {
                $site = $_
                $config = Get-WebConfiguration "/system.webServer/security/requestFiltering/verbs" "IIS:\Sites\$($site.Name)"
                $optionsVerb = $config | 
                    Select-Object -ExpandProperty Collection |
                    Where-Object { $_.verb -eq "OPTIONS" }
                
                @{
                    Name = $site.Name
                    OptionsEnabled = if ($optionsVerb) { $optionsVerb.allowed } else { $true }
                    HasExplicitConfig = [bool]$optionsVerb
                    Path = $site.PhysicalPath
                }
            }
        }

        $fixedSites = @()
        $skippedSites = @()

        foreach ($site in ($websiteStatus | Where-Object { $_.OptionsEnabled -or -not $_.HasExplicitConfig })) {
            Write-Host "`nWebsite Details:" -ForegroundColor Cyan
            Write-Host "  Name: $($site.Name)"
            Write-Host "  Path: $($site.Path)"
            $statusMessage = if ($site.HasExplicitConfig) { 'explicitly allowed' } else { 'allowed by default' }
            Write-Host "  OPTIONS method is currently $statusMessage"
            Write-Host "Would you like to explicitly deny OPTIONS method for this site? (y/N): " -ForegroundColor Yellow -NoNewline
            $response = Read-Host
            
            if ($response -eq 'y') {
                Write-Host "  Explicitly denying OPTIONS method..." -NoNewline
                
                $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    param($siteName)
                    
                    try {
                        # Remove any existing OPTIONS configuration first
                        $existingConfig = Get-WebConfiguration "/system.webServer/security/requestFiltering/verbs/add[@verb='OPTIONS']" "IIS:\Sites\$siteName"
                        if ($existingConfig) {
                            Clear-WebConfiguration "/system.webServer/security/requestFiltering/verbs/add[@verb='OPTIONS']" "IIS:\Sites\$siteName"
                        }

                        # Add explicit deny for OPTIONS
                        Add-WebConfigurationProperty -PSPath "IIS:\Sites\$siteName" `
                            -Filter "system.webServer/security/requestFiltering/verbs" `
                            -Name "." `
                            -Value @{verb='OPTIONS';allowed='false'}
                        
                        # Ensure WebDAV doesn't override our settings
                        Set-WebConfigurationProperty -PSPath "IIS:\Sites\$siteName" `
                            -Filter "system.webServer/security/requestFiltering/verbs" `
                            -Name "applyToWebDAV" `
                            -Value "false"
                        
                        return @{ Success = $true }
                    }
                    catch {
                        return @{
                            Success = $false
                            Error = $_.Exception.Message
                        }
                    }
                } -ArgumentList $site.Name
                
                if ($result.Success) {
                    Write-Host "Success!" -ForegroundColor Green
                    $fixedSites += $site.Name
                }
                else {
                    Write-Host "Failed!" -ForegroundColor Red
                    Write-Host "  Error: $($result.Error)" -ForegroundColor Red
                }
            }
            else {
                Write-Host "  Skipped." -ForegroundColor Yellow
                $skippedSites += $site.Name
            }
        }

        Write-Host "`nRemediation Summary:" -ForegroundColor Cyan
        if ($fixedSites.Count -gt 0) {
            Write-Host ('✓ OPTIONS method explicitly denied on: {0}' -f ($fixedSites -join ', ')) -ForegroundColor Green
        }
        if ($skippedSites.Count -gt 0) {
            Write-Host ('! Skipped sites: {0}' -f ($skippedSites -join ', ')) -ForegroundColor Yellow
        }
        if ($fixedSites.Count -eq 0 -and $skippedSites.Count -eq 0) {
            Write-Host "No sites required remediation" -ForegroundColor Green
        }

        # Verify the changes
        $verifyResult = Check-HTTPOptions -ComputerName $ComputerName
        if ($verifyResult.Status -eq "OK") {
            Write-Verbose "Verification passed - all sites are now properly configured"
            return $true
        }
        else {
            Write-Warning "Verification failed: $($verifyResult.Details)"
            return $false
        }
    }
    catch {
        Write-Error "Failed to fix HTTP OPTIONS method: $_"
        return $false
    }
}