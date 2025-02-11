function Check-WeakCiphers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 28
        Name = "Weak Cryptographic Cipher Suites"
        Status = "OK"
        Details = "All configured cipher suites meet security requirements"
    }

    try {
        Write-Verbose "Checking weak ciphers on $ComputerName"
        Write-Verbose "Initiating remote registry check for cipher configurations"

        $weakCiphers = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Write-Verbose "Starting cipher check on local system"
            
            # Get and display current cipher suite order
            Write-Verbose "Current Cipher Suite Order:"
            $currentCipherSuites = Get-TlsCipherSuite
            
            # Only try to get properties if we have cipher suites
            if ($currentCipherSuites) {
                Write-Verbose "Cipher Suite Properties Available:"
                $firstCipher = $currentCipherSuites | Select-Object -First 1
                if ($firstCipher) {
                    Write-Verbose ($firstCipher | Get-Member | Format-Table | Out-String)
                }
            }
            
            # Try to get cipher names using different possible property names
            $currentCipherOrder = @()
            if ($currentCipherSuites) {
                $currentCipherOrder = $currentCipherSuites | ForEach-Object {
                    if ($_.Name) {
                        $_.Name
                    } elseif ($_.CipherSuite) {
                        $_.CipherSuite
                    } else {
                        $_.ToString()
                    }
                }
            }
            
            Write-Verbose "Current Cipher Suites configured:"
            $currentCipherOrder | ForEach-Object { Write-Verbose "  $_" }
            
            # Get current cipher configuration using registry
            $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
            Write-Verbose "Checking registry path: $regPath"
            
            # Define weak ciphers to check
            $weakCiphersList = @(
                'NULL',
                'DES 56/56',
                'RC2 40/128',
                'RC2 56/128',
                'RC2 128/128',
                'RC4 40/128',
                'RC4 56/128',
                'RC4 64/128',
                'RC4 128/128',
                'Triple DES 168'
            )
            Write-Verbose "Checking for these weak ciphers: $($weakCiphersList -join ', ')"

            $foundWeakCiphers = @()

            # Check if base path exists
            if (-not (Test-Path $regPath)) {
                Write-Verbose "Base registry path does not exist. This might indicate no cipher configurations are present."
                
                # Check for weak ciphers in the current cipher suite order
                foreach ($cipher in $currentCipherOrder) {
                    if ($cipher -match 'NULL|RC4|RC2|DES|3DES|MD5|SHA1') {
                        Write-Verbose "Found weak cipher in current configuration: $cipher"
                        $foundWeakCiphers += $cipher
                    }
                }
            }
            else {
                Write-Verbose "Base registry path found, checking individual cipher configurations"

                # Check registry-based cipher configurations
                foreach ($cipher in $weakCiphersList) {
                    $cipherPath = Join-Path $regPath $cipher
                    Write-Verbose "Checking cipher path: $cipherPath"
                    
                    if (Test-Path $cipherPath) {
                        Write-Verbose "Found cipher configuration for: $cipher"
                        $cipherProps = Get-ItemProperty -Path $cipherPath
                        Write-Verbose "Cipher $cipher properties: $($cipherProps | ConvertTo-Json)"
                        
                        if ($null -eq $cipherProps.Enabled) {
                            Write-Verbose "Cipher $cipher has no 'Enabled' property - treating as enabled"
                            $foundWeakCiphers += $cipher
                        }
                        elseif ($cipherProps.Enabled -ne 0) {
                            Write-Verbose "Cipher $cipher is enabled (Value: $($cipherProps.Enabled))"
                            $foundWeakCiphers += $cipher
                        }
                        else {
                            Write-Verbose "Cipher $cipher is properly disabled"
                        }
                    }
                    else {
                        Write-Verbose "No registry configuration found for cipher: $cipher"
                    }
                }

                # Also check current cipher suite order for weak ciphers
                foreach ($cipher in $currentCipherOrder) {
                    if ($cipher -match 'NULL|RC4|RC2|DES|3DES|MD5|SHA1') {
                        if ($foundWeakCiphers -notcontains $cipher) {
                            Write-Verbose "Found additional weak cipher in current configuration: $cipher"
                            $foundWeakCiphers += $cipher
                        }
                    }
                }
            }

            Write-Verbose "Completed cipher check. Found weak ciphers: $($foundWeakCiphers.Count)"
            return $foundWeakCiphers
        } -Verbose

        Write-Verbose "Remote command completed. Processing results."
        Write-Verbose "Found weak ciphers: $($weakCiphers.Count)"
        
        if ($weakCiphers -and $weakCiphers.Count -gt 0) {
            Write-Verbose "Weak ciphers detected: $($weakCiphers -join ', ')"
            $result.Status = "WARNING"
            $result.Details = "Weak cipher suites detected: $($weakCiphers -join ', ')"
        }
        else {
            Write-Verbose "No weak ciphers detected"
        }

        Write-Verbose "Check completed. Status: $($result.Status)"
    }
    catch {
        Write-Verbose "Error occurred during check: $_"
        $result.Status = "WARNING"
        $result.Details = "Error checking cipher suites: $_"
        Write-Verbose "Error during check: $_"
    }

    return $result
} 