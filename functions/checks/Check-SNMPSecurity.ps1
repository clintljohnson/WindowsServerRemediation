function Check-SNMPSecurity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 14
        Name = "SNMP Security Configuration"
        Status = "OK"
        Details = "SNMP service is not installed"
    }

    try {
        Write-Verbose "Checking SNMP security configuration on $ComputerName"

        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            # Check if SNMP service exists
            $snmpService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
            
            if ($null -eq $snmpService) {
                return @{ Installed = $false }
            }

            $warnings = @()

            # Get SNMP configuration from registry
            $communities = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -ErrorAction SilentlyContinue
            $security = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\Security" -ErrorAction SilentlyContinue

            # Check SNMP version
            if ($security.PSObject.Properties.Name -notcontains "SnmpVersion" -or $security.SnmpVersion -lt 3) {
                $warnings += "SNMP version is not set to v3"
            }

            # Check for default community strings
            $defaultCommunities = @('public', 'private', 'community')
            foreach ($community in $communities.PSObject.Properties.Name) {
                if ($defaultCommunities -contains $community.ToLower()) {
                    $warnings += "Default community string '$community' is in use"
                }
            }

            return @{
                Installed = $true
                Warnings = $warnings
            }
        }

        if ($checkResult.Installed) {
            if ($checkResult.Warnings.Count -gt 0) {
                $result.Status = "WARNING"
                $result.Details = $checkResult.Warnings -join "; "
            } else {
                $result.Details = "SNMP is properly configured with v3 and non-default credentials"
            }
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking SNMP security on $ComputerName`: $_"
    }

    return $result
} 