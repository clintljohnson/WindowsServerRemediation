function Fix-MD5SHA1Ciphers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for MD5/SHA1 cipher suites on $ComputerName"

    try {
        # First check current state
        $currentState = Check-MD5SHA1Ciphers -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - MD5/SHA1 cipher suites are already properly configured"
            return $true
        }

        # Apply fix
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            try {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"
                
                # Ensure base path exists
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }

                # Configure MD5
                $md5Path = Join-Path $regPath "MD5"
                if (-not (Test-Path $md5Path)) {
                    New-Item -Path $md5Path -Force | Out-Null
                }
                Set-ItemProperty -Path $md5Path -Name "Enabled" -Value 0 -Type DWord

                # Configure SHA1
                $sha1Path = Join-Path $regPath "SHA1"
                if (-not (Test-Path $sha1Path)) {
                    New-Item -Path $sha1Path -Force | Out-Null
                }
                Set-ItemProperty -Path $sha1Path -Name "Enabled" -Value 0 -Type DWord

                Write-Verbose "Successfully disabled MD5 and SHA1 cipher suites"
                return $true
            }
            catch {
                Write-Error "Failed to configure MD5/SHA1 cipher suites: $_"
                return $false
            }
        }

        if ($result) {
            Write-Host "Successfully disabled MD5 and SHA1 cipher suites" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-MD5SHA1Ciphers -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed"
                return $false
            }
        }
        
        Write-Warning "Failed to apply fix"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 