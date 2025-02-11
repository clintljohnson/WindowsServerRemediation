function Fix-SNMPSecurity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for SNMP Security on $ComputerName"

    try {
        # First get the current state using the check function
        $currentState = Check-SNMPSecurity -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                # Check if SNMP service exists
                $snmpService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
                
                if ($null -eq $snmpService) {
                    Write-Verbose "SNMP service is not installed - no fix needed"
                    return $true
                }

                # Set SNMP to v3
                $securityPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\Security"
                if (-not (Test-Path $securityPath)) {
                    New-Item -Path $securityPath -Force | Out-Null
                }
                Set-ItemProperty -Path $securityPath -Name "SnmpVersion" -Value 3 -Type DWord
                Write-Verbose "Set SNMP version to 3"

                # Remove default community strings
                $communitiesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
                if (Test-Path $communitiesPath) {
                    $defaultCommunities = @('public', 'private', 'community')
                    $communities = Get-ItemProperty -Path $communitiesPath
                    
                    foreach ($community in $communities.PSObject.Properties.Name) {
                        if ($defaultCommunities -contains $community.ToLower()) {
                            Remove-ItemProperty -Path $communitiesPath -Name $community
                            Write-Verbose "Removed default community string: $community"
                        }
                    }
                }

                # Restart SNMP service
                Restart-Service -Name "SNMP" -Force
                Write-Verbose "Restarted SNMP service"

                return $true
            }
            catch {
                Write-Error "Failed to apply fix: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully applied SNMP security fixes" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-SNMPSecurity -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply SNMP security fixes"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 