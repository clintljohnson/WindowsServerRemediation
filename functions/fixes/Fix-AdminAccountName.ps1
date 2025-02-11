function Fix-AdminAccountName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$true,
                  HelpMessage="Enter the new name for the Administrator account")]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[a-zA-Z0-9_-]{1,20}$')]
        [string]$NewName
    )
    
    <#
    .SYNOPSIS
        Renames the built-in Administrator account for security purposes.
    .DESCRIPTION
        Modifies the following:
        - Renames the built-in Administrator account (SID ending in -500)
        - Verifies the change was successful
    .NOTES
        Requires administrative privileges on the target machine.
        The new name must be 1-20 characters and contain only letters, numbers, underscores, or hyphens.
    #>

    Write-Verbose "Starting fix operation for Admin Account Name on $ComputerName"
    
    try {
        # Check current state first
        $currentState = Check-AdminAccountName -ComputerName $ComputerName
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - admin account name is already compliant"
            return $true
        }

        Write-Verbose "Proceeding with rename operation to '$NewName'"

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($NewName)
            
            try {
                Write-Verbose "Locating Administrator account"
                $adminAccount = Get-CimInstance -ClassName Win32_UserAccount `
                                              -Filter "LocalAccount=True AND SID LIKE '%-500'" `
                                              -ErrorAction Stop

                if (-not $adminAccount) {
                    throw "Unable to locate Administrator account"
                }
                
                Write-Verbose "Found admin account: $($adminAccount.Name)"
                if ($adminAccount.Name -eq $NewName) {
                    Write-Verbose "Account is already named '$NewName'"
                    return @{
                        Success = $true
                        Message = "Account already has desired name"
                    }
                }
                
                Write-Verbose "Initiating rename operation"
                $result = Invoke-CimMethod -InputObject $adminAccount `
                                         -MethodName Rename `
                                         -Arguments @{ Name = $NewName } `
                                         -ErrorAction Stop

                if ($result.ReturnValue -ne 0) {
                    throw "Rename operation failed with code: $($result.ReturnValue)"
                }

                return @{
                    Success = $true
                    Message = "Account renamed successfully"
                }
            }
            catch {
                return @{
                    Success = $false
                    Message = "Failed to apply fix: $_"
                }
            }
        } -ArgumentList $NewName

        if ($result.Success) {
            Write-Host $result.Message -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-AdminAccountName -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed: $($verifyResult.Details)"
                return $false
            }
        }
        
        Write-Warning $result.Message
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 