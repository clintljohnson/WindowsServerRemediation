function Check-WinVerifyTrust {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 42
        Name = "WinVerifyTrust Signature Validation Check"
        Status = "OK"
        Details = "EnableCertPaddingCheck is properly configured in both registry paths"
    }

    try {
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $paths = @(
                "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config",
                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
            )
            $valueName = "EnableCertPaddingCheck"
            $results = @{}
            
            foreach ($path in $paths) {
                # Check if the registry key exists
                $keyExists = Test-Path -Path $path
                
                # Check if the value exists and get its data
                if ($keyExists) {
                    try {
                        $regKey = Get-Item -Path $path
                        $value = $regKey.GetValue($valueName, $null)
                        $valueType = $regKey.GetValueKind($valueName)
                        
                        Write-Verbose "Path: $path"
                        Write-Verbose "Value: $value"
                        Write-Verbose "ValueType: $valueType"
                        
                        $results[$path] = @{
                            KeyExists = $true
                            ValueExists = ($null -ne $value)
                            Value = $value
                            ValueType = $valueType
                        }
                    }
                    catch {
                        Write-Verbose "Error accessing registry value: $_"
                        $results[$path] = @{
                            KeyExists = $true
                            ValueExists = $false
                            Value = $null
                            ValueType = $null
                        }
                    }
                } else {
                    $results[$path] = @{
                        KeyExists = $false
                        ValueExists = $false
                        Value = $null
                        ValueType = $null
                    }
                }
            }
            return $results
        }

        $missingPaths = @()
        foreach ($path in $checkResult.Keys) {
            $pathResult = $checkResult[$path]
            Write-Verbose "Checking path: $path"
            Write-Verbose "Exists: $($pathResult.KeyExists)"
            Write-Verbose "Value exists: $($pathResult.ValueExists)"
            Write-Verbose "Value: $($pathResult.Value)"
            Write-Verbose "Value type: $($pathResult.ValueType)"

            if (-not $pathResult.KeyExists -or 
                -not $pathResult.ValueExists -or 
                $pathResult.Value -ne "1" -or 
                $pathResult.ValueType -ne 1) {  # Registry.ValueKind.String = 1
                $missingPaths += $path
            }
        }

        if ($missingPaths.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = "WinVerifyTrust signature validation vulnerability (CVE-2013-3900) mitigation is not properly configured. " +
                            "The following paths need attention: $($missingPaths -join ', ')"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error performing WinVerifyTrust check: $_"
    }

    return $result
} 