function Fix-PasswordRestrictions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for General Password Restrictions on $ComputerName"

    try {
        # First check current state
        $currentState = Check-PasswordRestrictions -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current password restrictions are compliant"
            return $true
        }

        Write-Verbose "Current issues: $($currentState.Details)"
        
        # Check if this is a domain-controlled policy
        if ($currentState.Details -match "Domain-controlled password policy") {
            Write-Warning "Cannot modify domain-controlled password policies via this tool."
            Write-Warning "Please contact your domain administrator to update the domain password policy."
            Write-Warning "GPO Path: Default Domain Policy > Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy"
            return $false
        }

        # If we get here, we're dealing with local policy
        Write-Verbose "Applying local password policy changes..."
        
        # Use Invoke-Command to run commands on remote computer
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $VerbosePreference = 'Continue'
            
            try {
                Write-Verbose "Creating security policy INF file"
                $infPath = [System.IO.Path]::GetTempFileName()
                $dbPath = [System.IO.Path]::GetTempFileName()

                $infContent = @"
[Unicode]
Unicode=yes
[System Access]
PasswordComplexity = 1
MinimumPasswordLength = 14
PasswordHistorySize = 24
MaximumPasswordAge = 90
MinimumPasswordAge = 0
[Version]
signature="$CHICAGO$"
Revision=1
"@

                Write-Verbose "Writing security policy to $infPath"
                Set-Content -Path $infPath -Value $infContent -Force
                
                Write-Verbose "Applying security policy changes"
                $result = secedit /configure /db $dbPath /cfg $infPath /quiet
                Write-Verbose "Secedit output: $result"
                
                Write-Verbose "Running gpupdate..."
                $gpResult = gpupdate /force
                Write-Verbose "GPUpdate output: $gpResult"
                
                return $true
            }
            catch {
                Write-Error "Failed to apply security policy: $_"
                return $false
            }
            finally {
                if (Test-Path $infPath) { Remove-Item $infPath -Force }
                if (Test-Path $dbPath) { Remove-Item $dbPath -Force }
            }
        } -Verbose

        if ($result) {
            Write-Host "Successfully applied local password restrictions" -ForegroundColor Green
            
            Write-Verbose "Waiting 15 seconds before verification..."
            Start-Sleep -Seconds 15
            
            # Verify the fix
            Write-Verbose "Running verification check..."
            $verifyResult = Check-PasswordRestrictions -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            Write-Warning "Fix applied but verification failed: $($verifyResult.Details)"
            return $false
        }
        
        Write-Warning "Failed to apply password restrictions"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 