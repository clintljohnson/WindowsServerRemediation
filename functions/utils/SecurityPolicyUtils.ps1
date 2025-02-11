function Get-SecurityPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('User_Rights')]
        [string]$Area,
        
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    try {
        # Create a temporary file to export the security policy
        $tempFile = [System.IO.Path]::GetTempFileName()
        
        # Export the current security policy
        $result = secedit /export /cfg $tempFile /quiet
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to export security policy"
        }

        # Read the security policy file
        $content = Get-Content $tempFile -Raw
        
        # Parse based on the area requested
        switch ($Area) {
            'User_Rights' {
                # Find the line containing the specified privilege
                if ($content -match "$Name\s*=\s*([^\r\n]+)") {
                    $accounts = $matches[1].Trim().Split(',', [StringSplitOptions]::RemoveEmptyEntries)
                    
                    # Convert SIDs to account names where possible
                    $accountNames = $accounts | ForEach-Object {
                        $sid = $_.Trim('*')
                        try {
                            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
                            $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
                            $objUser.Value
                        }
                        catch {
                            $_  # Return original value if translation fails
                        }
                    }
                    
                    return @{ FullName = $accountNames }
                }
                return @{ FullName = @() }  # Return empty array if no matches
            }
        }
    }
    catch {
        Write-Error "Error in Get-SecurityPolicy: $_"
        throw
    }
    finally {
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
    }
}

function Remove-AccountFromUserRight {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Account,
        
        [Parameter(Mandatory=$true)]
        [string]$Right
    )

    try {
        # Create a temporary file for the security database
        $tempDb = [System.IO.Path]::GetTempFileName()
        
        # Create a temporary file for the security policy
        $tempPolicy = [System.IO.Path]::GetTempFileName()
        
        # Export the current security policy
        $result = secedit /export /cfg $tempPolicy /quiet
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to export security policy"
        }

        # Read the current policy
        $content = Get-Content $tempPolicy -Raw
        
        # Get current accounts for the right
        $accounts = @()
        if ($content -match "$Right\s*=\s*([^\r\n]+)") {
            $accounts = $matches[1].Trim().Split(',', [StringSplitOptions]::RemoveEmptyEntries)
        }
        
        # Remove the specified account
        $accounts = $accounts | Where-Object { $_ -ne $Account }
        
        # Create the new policy content
        $newContent = $content -replace "$Right\s*=\s*[^\r\n]+", "$Right = $($accounts -join ',')"
        
        # Save the new policy
        $newContent | Set-Content $tempPolicy -Force
        
        # Import the new policy
        $result = secedit /configure /db $tempDb /cfg $tempPolicy /quiet
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to import security policy"
        }
        
        return $true
    }
    catch {
        Write-Error "Error in Remove-AccountFromUserRight: $_"
        throw
    }
    finally {
        # Cleanup temporary files
        @($tempDb, $tempPolicy) | ForEach-Object {
            if (Test-Path $_) {
                Remove-Item $_ -Force
            }
        }
    }
} 