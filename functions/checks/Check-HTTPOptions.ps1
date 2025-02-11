function Check-HTTPOptions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 46
        Name = "HTTP OPTIONS Method Check"
        Status = "OK"
        Details = "HTTP OPTIONS method is properly restricted on all IIS websites"
    }

    try {
        Write-Verbose "Checking if IIS is installed on $ComputerName"
        # Check if IIS is installed
        $iisCheck = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-WindowsFeature Web-Server | Select-Object -ExpandProperty Installed
        }

        if (-not $iisCheck) {
            Write-Verbose "IIS is not installed on $ComputerName"
            $result.Status = "OK"
            $result.Details = "IIS is not installed on this server"
            return $result
        }

        Write-Verbose "IIS is installed. Checking global and website-specific OPTIONS method status..."

        # Get global and website-specific OPTIONS status
        $statusCheck = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Import-Module WebAdministration
            
            # Check global settings first
            $globalConfig = Get-WebConfiguration "/system.webServer/security/requestFiltering/verbs" "MACHINE/WEBROOT/APPHOST"
            
            # Get all verbs and their status
            $globalVerbs = $globalConfig | 
                Select-Object -ExpandProperty Collection |
                Where-Object { $_.verb -eq "OPTIONS" }
            
            $globalOptionsEnabled = if ($globalVerbs) {
                # If OPTIONS is configured, check if it's explicitly allowed
                $globalVerbs.allowed -eq $true
            } else {
                # If OPTIONS is not configured, consider it allowed (default IIS behavior)
                $true
            }

            # Get website-specific settings
            $sites = Get-Website | ForEach-Object {
                $site = $_
                Write-Verbose "Checking website: $($site.Name)"
                
                try {
                    $config = Get-WebConfiguration "/system.webServer/security/requestFiltering/verbs" "IIS:\Sites\$($site.Name)"
                    
                    # Get OPTIONS verb status
                    $optionsVerb = $config | 
                        Select-Object -ExpandProperty Collection |
                        Where-Object { $_.verb -eq "OPTIONS" }
                    
                    $optionsEnabled = if ($optionsVerb) {
                        # If OPTIONS is configured, check if it's explicitly allowed
                        $optionsVerb.allowed -eq $true
                    } else {
                        # If OPTIONS is not configured, inherit from global or default to allowed
                        $globalOptionsEnabled
                    }
                    
                    Write-Verbose "Website $($site.Name) OPTIONS status: $(if ($optionsEnabled) { 'Enabled' } else { 'Disabled' })"
                    
                    # Extract directory name from physical path
                    $dirName = if ($site.PhysicalPath) {
                        Split-Path $site.PhysicalPath -Leaf
                    } else {
                        $site.Name
                    }
                    
                    @{
                        Name = $site.Name
                        OptionsEnabled = $optionsEnabled
                        Path = $site.PhysicalPath
                        State = $site.State
                        Directory = $dirName
                    }
                }
                catch {
                    Write-Warning "Error checking website $($site.Name): $_"
                    @{
                        Name = $site.Name
                        OptionsEnabled = $null
                        Path = $site.PhysicalPath
                        State = $site.State
                        Directory = Split-Path (if ($site.PhysicalPath) { $site.PhysicalPath } else { $site.Name }) -Leaf
                        Error = $_.Exception.Message
                    }
                }
            }

            @{
                GlobalOptionsEnabled = $globalOptionsEnabled
                Sites = $sites
            }
        } -Verbose:$VerbosePreference

        Write-Verbose "Global OPTIONS status: $($statusCheck.GlobalOptionsEnabled)"

        # Process results
        $issues = @()
        $alreadyDenied = @()
        
        # Check global configuration
        if ($statusCheck.GlobalOptionsEnabled) {
            $issues += "IIS Global Configuration"
        } else {
            $alreadyDenied += "IIS Global Configuration"
        }

        # Check site-specific configurations
        $enabledSites = $statusCheck.Sites | Where-Object { $_.OptionsEnabled }
        $deniedSites = $statusCheck.Sites | Where-Object { 
            # Only consider it denied if OPTIONS is explicitly configured as not allowed
            $_.OptionsEnabled -eq $false -and 
            ($config | Select-Object -ExpandProperty Collection | Where-Object { $_.verb -eq "OPTIONS" })
        }
        
        if ($enabledSites) {
            $affectedSites = ($enabledSites | ForEach-Object { $_.Directory }) -join ", "
            $issues += $affectedSites
        }
        
        if ($deniedSites) {
            $deniedSiteNames = ($deniedSites | ForEach-Object { $_.Directory }) -join ", "
            $alreadyDenied += $deniedSiteNames
        }

        $checkedSites = ($statusCheck.Sites | ForEach-Object { $_.Directory } | Sort-Object) -join ", "

        if ($issues) {
            $result.Status = "WARNING"
            $result.Details = "HTTP OPTIONS method is not explicitly denied (default allowed) on: $($issues -join ', ')"
            if ($alreadyDenied) {
                $result.Details += " | Explicitly denied on: $($alreadyDenied -join ', ')"
            }
            $result.Details += " | Checked sites: $checkedSites"
        } else {
            $result.Details = "HTTP OPTIONS method is properly restricted globally and on all IIS websites"
            if ($alreadyDenied) {
                $result.Details += " | Explicitly denied on: $($alreadyDenied -join ', ')"
            } else {
                $result.Details += " | No explicit denials configured"
            }
            $result.Details += " | Checked: $checkedSites"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking HTTP OPTIONS method: $_"
        Write-Verbose "Error during check: $_"
    }

    Write-Verbose "Check completed with status: $($result.Status)"
    return $result
} 