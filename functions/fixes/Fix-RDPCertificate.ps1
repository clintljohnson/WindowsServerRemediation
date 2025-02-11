function Fix-RDPCertificate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting RDP certificate configuration fix for $ComputerName"
    
    try {
        # First check current state
        $currentState = Check-RDPCertificate -ComputerName $ComputerName
        if ($currentState.Status -eq "OK") {
            Write-Verbose "Certificate already properly configured"
            return $true
        }

        # Default CA thumbprint for MDOT-CA-256
        $CAThumbprint = "16ef0f59190b83d77be39fe73c29270ef9d3dea9"
        Write-Verbose "Using CA Thumbprint: $CAThumbprint"

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
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
                Write-Verbose "Searching for valid certificate in store"
                # Get certificates from local machine store
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
                $store.Open("ReadOnly")
                
                # Find certificate with server's CN that's signed by our CA
                $serverName = $env:COMPUTERNAME
                $validCert = $store.Certificates | Where-Object {
                    $_.Subject -match "CN=$serverName" -and 
                    $_.HasPrivateKey -and 
                    (Test-CertificateChain -Cert $_ -CAThumbprint $CAThumbprint)
                } | Select-Object -First 1

                if (-not $validCert) {
                    throw "No valid certificate found signed by MDOT-CA-256"
                }

                Write-Verbose "Found valid certificate, configuring RDP"
                # Configure RDP to use the certificate
                $certHash = $validCert.Thumbprint
                
                # Set certificate using wmic
                $wmicCommand = "wmic /namespace:\\root\cimv2\TerminalServices PATH Win32_TSGeneralSetting Set SSLCertificateSHA1Hash=`"$certHash`""
                Invoke-Expression $wmicCommand

                # Update registry
                $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
                Set-ItemProperty -Path $path -Name "SSLCertificateSHA1Hash" -Value $certHash

                # Update Terminal Services configuration
                $ts = Get-WmiObject -Namespace "root/cimv2/TerminalServices" -Class "Win32_TSGeneralSetting" -Filter "TerminalName='RDP-tcp'"
                $ts.SSLCertificateSHA1Hash = $certHash
                $ts.Put() | Out-Null

                Write-Verbose "Restarting RDP services"
                # Restart RDP-related services
                $services = @("TermService", "UmRdpService", "SessionEnv")
                foreach ($service in $services) {
                    if (Get-Service $service -ErrorAction SilentlyContinue) {
                        Stop-Service $service -Force
                        Start-Sleep -Seconds 2
                        Start-Service $service
                    }
                }

                return $true
            }
            catch {
                Write-Error $_
                return $false
            }
            finally {
                if ($store) { $store.Close() }
            }
        } -ArgumentList $CAThumbprint

        if ($result) {
            Write-Verbose "Fix applied successfully, verifying..."
            # Verify the fix
            $verifyResult = Check-RDPCertificate -ComputerName $ComputerName
            return ($verifyResult.Status -eq "OK")
        }
        return $false
    }
    catch {
        Write-Error "Failed to fix RDP certificate configuration: $_"
        return $false
    }
} 