function Check-MD5SHA1Ciphers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 36
        Name = "MD5 and SHA1 Cipher Suites"
        Status = "OK"
        Details = "MD5 and SHA1 cipher suites are properly disabled"
    }

    try {
        Write-Verbose "Checking MD5 and SHA1 cipher suites on $ComputerName"
        
        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $weakCiphers = @()
            
            # Check registry for MD5 and SHA1 cipher suites
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"
            
            # Check MD5
            $md5Path = Join-Path $regPath "MD5"
            if (Test-Path $md5Path) {
                $md5Enabled = (Get-ItemProperty -Path $md5Path -ErrorAction SilentlyContinue).Enabled
                if ($md5Enabled -ne 0) {
                    $weakCiphers += "MD5"
                }
            }
            
            # Check SHA1
            $sha1Path = Join-Path $regPath "SHA1"
            if (Test-Path $sha1Path) {
                $sha1Enabled = (Get-ItemProperty -Path $sha1Path -ErrorAction SilentlyContinue).Enabled
                if ($sha1Enabled -ne 0) {
                    $weakCiphers += "SHA1"
                }
            }
            
            return @{
                WeakCiphers = $weakCiphers
                MD5Exists = Test-Path $md5Path
                SHA1Exists = Test-Path $sha1Path
            }
        }

        if ($checkResult.WeakCiphers.Count -gt 0) {
            $result.Status = "WARNING"
            $result.Details = "The following weak hash algorithms are enabled: $($checkResult.WeakCiphers -join ', ')"
        }
        elseif (-not ($checkResult.MD5Exists -and $checkResult.SHA1Exists)) {
            $result.Status = "WARNING"
            $result.Details = "Registry keys for MD5/SHA1 control are missing. Hash algorithms may not be properly restricted."
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking MD5/SHA1 cipher suites: $_"
    }

    return $result
} 