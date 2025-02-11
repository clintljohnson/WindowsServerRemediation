# Add function documentation
<#
.SYNOPSIS
    Fixes password complexity settings for administrator accounts.
.DESCRIPTION
    Configures the following password security settings:
    - Minimum password length (14 characters)
    - Password complexity requirement (enabled)
    - Maximum password age (365 days)
    - Password history size (24 passwords)
.PARAMETER ComputerName
    The remote computer to configure password settings on.
#>

function Fix-AdminPasswordComplexity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for AdminPasswordComplexity on $ComputerName"

    try {
        # First check current state
        $currentState = Check-AdminPasswordComplexity -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current state is compliant"
            return $true
        }

        # Step 1: Fix complexity requirements first
        $complexityIssues = $currentState.Details -match "complexity is not enabled|Minimum password length|Password history size"
        if ($complexityIssues) {
            Write-Verbose "Fixing password complexity settings..."
            
            # Use Invoke-Command for remote execution
            $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                try {
                    # Create temporary files on the remote system
                    $tempFile = "$env:TEMP\secpol.cfg"
                    $exportFile = "$env:TEMP\secpol.inf"
                    
                    # Export current security policy
                    secedit /export /cfg $tempFile | Out-Null
                    
                    # Read the current policy
                    $policy = Get-Content $tempFile -Raw
                    
                    # Update password policy settings
                    $policy = $policy -replace "MinimumPasswordLength\s*=.*", "MinimumPasswordLength = 14"
                    $policy = $policy -replace "PasswordComplexity\s*=.*", "PasswordComplexity = 1"
                    $policy = $policy -replace "MaximumPasswordAge\s*=.*", "MaximumPasswordAge = 365"
                    $policy = $policy -replace "PasswordHistorySize\s*=.*", "PasswordHistorySize = 24"
                    
                    # Save the modified policy
                    $policy | Set-Content $exportFile -Force
                    
                    # Apply the new policy
                    secedit /configure /db "$env:TEMP\secpol.sdb" /cfg $exportFile /areas SECURITYPOLICY | Out-Null
                    
                    # Cleanup
                    Remove-Item "$env:TEMP\secpol.*" -Force -ErrorAction SilentlyContinue
                    
                    return $true
                }
                catch {
                    Write-Error "Failed to apply complexity settings: $_"
                    return $false
                }
            }

            if (-not $result) {
                Write-Error "Failed to apply password complexity settings"
                return $false
            }

            Write-Host "Successfully configured password complexity requirements" -ForegroundColor Green
            
            # Verify complexity settings
            $verifyResult = Check-AdminPasswordComplexity -ComputerName $ComputerName
            if ($verifyResult.Status -eq "WARNING" -and $verifyResult.Details -match "complexity|length|history") {
                Write-Warning "Failed to verify complexity settings"
                return $false
            }
        }

        # Step 2: Set password expiration for Administrator account
        Write-Verbose "Checking Administrator account password expiration settings..."
        $expirationResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                # Find Administrator account by SID
                $adminAccount = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'" | 
                    Where-Object { $_.SID -match "-500$" }
                
                if (-not $adminAccount) {
                    throw "Could not find Administrator account (SID ending in -500)"
                }

                Write-Verbose "Setting password expiration for account: $($adminAccount.Name)"
                
                # Use ADSI to modify the account
                $computer = [ADSI]"WinNT://$env:COMPUTERNAME"
                $user = $computer.Children | Where-Object { $_.SchemaClassName -eq 'user' -and $_.Name -eq $adminAccount.Name }
                
                if (-not $user) {
                    throw "Could not find administrator account using ADSI"
                }

                # UserFlags: 65536 is the flag for "Password never expires"
                # Get current flags and remove the "never expires" flag if present
                $currentFlags = $user.UserFlags.Value
                $newFlags = $currentFlags -band (-bnot 65536)
                
                Write-Verbose "Current user flags: $currentFlags"
                Write-Verbose "New user flags: $newFlags"
                
                # Set the new flags
                $user.UserFlags = $newFlags
                $user.SetInfo()

                # Verify the change
                $user.RefreshCache()
                $updatedFlags = $user.UserFlags.Value
                
                if ($updatedFlags -band 65536) {
                    throw "Failed to remove 'Password never expires' flag"
                }

                # Set maximum password age using local security policy
                $maxPasswordAge = 364
                $secConfig = [System.IO.Path]::GetTempFileName()
                secedit /export /cfg $secConfig | Out-Null
                $content = Get-Content $secConfig
                $content = $content -replace "MaximumPasswordAge\s*=\s*\d+", "MaximumPasswordAge = $maxPasswordAge"
                $content | Set-Content $secConfig
                secedit /configure /db secedit.sdb /cfg $secConfig /areas SECURITYPOLICY | Out-Null
                Remove-Item $secConfig -Force

                return @{
                    Success = $true
                    Message = "Password expiration successfully configured for $($adminAccount.Name)"
                }
            }
            catch {
                return @{
                    Success = $false
                    Message = "Failed to configure password expiration: $_"
                }
            }
        }

        if (-not $expirationResult.Success) {
            Write-Warning $expirationResult.Message
            return $false
        }
        else {
            Write-Verbose $expirationResult.Message
        }

        # Step 3: Check if password update is needed
        $currentState = Check-AdminPasswordComplexity -ComputerName $ComputerName
        if ($currentState.Details -match "not been changed in (\d+) days") {
            Write-Host "Administrator password needs to be updated." -ForegroundColor Yellow
            
            # Prompt for new password securely
            $newPassword = Read-Host -Prompt "Enter new administrator password" -AsSecureString
            $confirmPassword = Read-Host -Prompt "Confirm new administrator password" -AsSecureString

            # Convert SecureString to plain text for comparison
            $BSTR1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPassword)
            $BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword)
            $pass1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR1)
            $pass2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)

            if ($pass1 -ne $pass2) {
                Write-Error "Passwords do not match"
                return $false
            }

            # Update the password on remote computer
            $updateResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                param($NewPass)
                try {
                    # Get Administrator account
                    $adminAccount = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'" | 
                        Where-Object { $_.SID -match "-500$" }
                    
                    # Update password
                    $result = net user $adminAccount.Name $NewPass
                    return $LASTEXITCODE -eq 0
                }
                catch {
                    Write-Error "Failed to update password: $_"
                    return $false
                }
            } -ArgumentList $pass1

            # Clear sensitive data from memory
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR1)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR2)
            Remove-Variable pass1, pass2

            if (-not $updateResult) {
                Write-Error "Failed to update administrator password"
                return $false
            }

            Write-Host "Successfully updated administrator password" -ForegroundColor Green
        }

        # Final verification
        $finalVerify = Check-AdminPasswordComplexity -ComputerName $ComputerName
        if ($finalVerify.Status -eq "OK") {
            Write-Verbose "All fixes verified successfully"
            return $true
        }
        else {
            Write-Warning "Some fixes could not be verified. Current state: $($finalVerify.Details)"
            return $false
        }
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 