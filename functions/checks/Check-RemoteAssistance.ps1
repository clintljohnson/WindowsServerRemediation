function Check-RemoteAssistance {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        [Parameter(Mandatory=$false)]
        [System.Collections.Hashtable]$Parameters
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)] Checking Remote Assistance settings"

    $result = @{
        CheckNumber = 4
        Category = "Security"
        Name = "Remote Assistance Configuration"
        Status = "OK"
        Details = "Remote Assistance is properly configured or disabled"
        Function = $MyInvocation.MyCommand.Name
        Reference = "MS Security Baseline, CIS Benchmark 18.8.49.1"
        Resolution = "Disable Remote Assistance or ensure it's properly configured in System Properties > Remote settings or via Group Policy"
    }

    try {
        $registryChecks = @(
            @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
                Properties = @(
                    @{
                        Name = "fAllowToGetHelp"
                        ExpectedValue = 0
                    }
                )
            }
        )

        $scriptBlock = {
            param($checks)
            $results = @()
            
            # Check registry settings
            foreach ($check in $checks) {
                if (Test-Path $check.Path) {
                    foreach ($prop in $check.Properties) {
                        $value = Get-ItemProperty -Path $check.Path -Name $prop.Name -ErrorAction SilentlyContinue
                        $results += @{
                            Name = $prop.Name
                            Value = if ($value) { $value.$($prop.Name) } else { $null }
                            Expected = $prop.ExpectedValue
                            Exists = if ($value) { $true } else { $false }
                        }
                    }
                }
                else {
                    $results += @{
                        Path = $check.Path
                        Exists = $false
                    }
                }
            }

            # Check Remote Assistance service status
            $raService = Get-Service -Name "RemoteAccess" -ErrorAction SilentlyContinue
            $results += @{
                Name = "RemoteAccessService"
                Status = if ($raService) { $raService.Status } else { "NotFound" }
            }

            # Check firewall rules related to Remote Assistance
            $fwRules = Get-NetFirewallRule -DisplayGroup "Remote Assistance" -ErrorAction SilentlyContinue
            $results += @{
                Name = "FirewallRules"
                Rules = $fwRules | Select-Object DisplayName, Enabled, Direction, Action
            }

            return $results
        }

        $checkResults = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $registryChecks

        $issues = @()

        # Analyze registry results
        foreach ($check in ($checkResults | Where-Object { $_.Name -eq "fAllowToGetHelp" })) {
            if (-not $check.Exists) {
                $issues += "Remote Assistance registry setting is missing"
            }
            elseif ($check.Value -ne $check.Expected) {
                $issues += "Remote Assistance is enabled (fAllowToGetHelp = $($check.Value))"
            }
        }

        # Analyze service status
        $serviceResult = $checkResults | Where-Object { $_.Name -eq "RemoteAccessService" }
        if ($serviceResult.Status -eq "Running") {
            $issues += "Remote Access service is running"
        }

        # Analyze firewall rules
        $fwResults = $checkResults | Where-Object { $_.Name -eq "FirewallRules" }
        $enabledInboundRules = $fwResults.Rules | Where-Object { $_.Enabled -and $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" }
        if ($enabledInboundRules) {
            $issues += "Found enabled inbound Remote Assistance firewall rules: $($enabledInboundRules.DisplayName -join ', ')"
        }

        if ($issues.Count -gt 0) {
            $result.Status = "Failed"
            $result.Details = "Remote Assistance configuration issues found: $($issues -join '; ')"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Details = "Failed to check Remote Assistance settings: $($_.Exception.Message)"
    }

    return $result
} 