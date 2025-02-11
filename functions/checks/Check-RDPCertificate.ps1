function Check-RDPCertificate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Checking RDP certificate configuration on $ComputerName"

    $result = @{
        CheckNumber = 44
        Name = "RDP Certificate Configuration"
        Status = "OK"
        Details = "RDP service is using a valid signed certificate"
    }

    try {
        # Default CA thumbprint for RDP Service Certificate
        $CAThumbprint = "16ef0f59190b83d77be39fe73c29270ef9d3dea9"

        Write-Verbose "Using CA Thumbprint: $CAThumbprint"

        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($CAThumbprint)

            function Test-CertificateChain {
                param($Cert, $CAThumbprint)
                $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
                $chain.Build($Cert) | Out-Null
                
                foreach ($element in $chain.ChainElements) {
                    if ($element.Certificate.Thumbprint -eq $CAThumbprint) {
                        return $true
                    }
                }
                return $false
            }

            try {
                Write-Verbose "Getting current RDP certificate configuration"
                # Get current RDP certificate hash
                $ts = Get-WmiObject -Namespace "root/cimv2/TerminalServices" `
                    -Class "Win32_TSGeneralSetting" -Filter "TerminalName='RDP-tcp'"
                $currentCertHash = $ts.SSLCertificateSHA1Hash

                # Get certificates from local machine store
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
                $store.Open("ReadOnly")

                # Find the certificate currently in use
                $currentCert = $store.Certificates | Where-Object { $_.Thumbprint -eq $currentCertHash }

                if ($currentCert -and (Test-CertificateChain -Cert $currentCert -CAThumbprint $CAThumbprint)) {
                    Write-Verbose "Found valid certificate in use"
                    return @{
                        Valid = $true
                        CertificateSubject = $currentCert.Subject
                        Thumbprint = $currentCert.Thumbprint
                        ExpirationDate = $currentCert.NotAfter
                    }
                }
                Write-Verbose "No valid certificate found"
                return @{ Valid = $false }
            }
            finally {
                if ($store) { $store.Close() }
            }
        } -ArgumentList $CAThumbprint

        if (-not $checkResult.Valid) {
            $result.Status = "WARNING"
            $result.Details = "RDP Service is not using a trusted Signed Certificate"
        }
        else {
            Write-Verbose "Found valid certificate: $($checkResult.CertificateSubject)"
            Write-Verbose "Expires: $($checkResult.ExpirationDate)"
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking RDP certificate: $_"
        Write-Verbose "Error occurred: $_"
    }

    return $result
} 
