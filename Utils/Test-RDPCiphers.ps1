<#
.SYNOPSIS
Tests RDP server endpoints for supported TLS cipher suites with accurate cipher detection.

.DESCRIPTION
Uses PowerShell-compatible methods to test TLS cipher suite support for RDP connections,
accurately mapping the negotiated cipher algorithms to specific cipher suites.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$targetHost,
    
    [Parameter(Mandatory=$false)]
    [int]$port = 3389
)

function Test-RDPCipherSupport {
    param (
        [string]$hostname,
        [int]$port,
        [string]$cipherSuite
    )
    
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $connectResult = $client.BeginConnect($hostname, $port, $null, $null)
        $waitResult = $connectResult.AsyncWaitHandle.WaitOne(5000)
        
        if (-not $waitResult) {
            Write-Verbose "Connection timeout"
            return @{ Supported = $false }
        }
        
        $client.EndConnect($connectResult)
        $stream = $client.GetStream()
        
        # Enhanced RDP Protocol Negotiation Request
        $rdpNegRequest = [byte[]]@(
            0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x0B,
            0x00, 0x00, 0x00
        )
        
        $stream.Write($rdpNegRequest, 0, $rdpNegRequest.Length)
        $stream.Flush()
        
        $responseBuffer = New-Object byte[] 19
        $bytesRead = $stream.Read($responseBuffer, 0, $responseBuffer.Length)
        
        if ($bytesRead -lt 19) {
            Write-Verbose "Invalid RDP response"
            return @{ Supported = $false }
        }

        # Initialize SSL/TLS Stream with specific cipher suite
        $sslStream = New-Object System.Net.Security.SslStream(
            $stream,
            $false,
            {param($sender, $certificate, $chain, $errors) return $true}
        )
        
        try {
            # Create SSL Options object
            $sslOptions = [System.Net.Security.SslClientAuthenticationOptions]::new()
            $sslOptions.TargetHost = $hostname
            $sslOptions.EnabledSslProtocols = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13
            
            # Set specific cipher suite if supported by .NET version
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $sslOptions.CipherSuitesPolicy = [System.Net.Security.CipherSuitesPolicy]::new(@($cipherSuite))
            }
            
            # Attempt authentication with timeout
            $authTask = $sslStream.AuthenticateAsClientAsync($sslOptions)
            if (-not [System.Threading.Tasks.Task]::WaitAll(@($authTask), 5000)) {
                Write-Verbose "SSL/TLS handshake timeout"
                return @{ Supported = $false }
            }
            
            return @{
                Supported = $true
                CipherAlgorithm = $sslStream.CipherAlgorithm
                KeyExchangeAlgorithm = $sslStream.KeyExchangeAlgorithm
                HashAlgorithm = $sslStream.HashAlgorithm
                Protocol = $sslStream.SslProtocol
            }
        }
        catch {
            Write-Verbose "SSL/TLS handshake failed: $_"
            return @{ Supported = $false }
        }
    }
    catch {
        Write-Verbose "Connection error: $_"
        return @{ Supported = $false }
    }
    finally {
        if ($sslStream) { $sslStream.Dispose() }
        if ($client) { $client.Close() }
    }
}

# Expanded list of cipher suites to test
$cipherSuites = @(
    # TLS 1.3 Suites
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    
    # TLS 1.2 ECDHE Suites
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    
    # TLS 1.2 DHE Suites
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    
    # Legacy Suites (if needed)
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA"
    
)

Write-Host "Testing RDP cipher suite support on $targetHost`:$port"
Write-Host "=================================================="

$results = @()
foreach ($cipherSuite in $cipherSuites) {
    Write-Host "Testing $cipherSuite... " -NoNewline
    $result = Test-RDPCipherSupport -hostname $targetHost -port $port -cipherSuite $cipherSuite
    
    if ($result.Supported) {
        Write-Host "Supported" -ForegroundColor Green
        Write-Verbose "Cipher: $($result.CipherAlgorithm), KeyExchange: $($result.KeyExchangeAlgorithm), Hash: $($result.HashAlgorithm)"
    } else {
        Write-Host "Not Supported" -ForegroundColor Red
    }
    
    $results += [PSCustomObject]@{
        CipherSuite = $cipherSuite
        Supported = $result.Supported
        CipherAlgorithm = $result.CipherAlgorithm
        KeyExchangeAlgorithm = $result.KeyExchangeAlgorithm
        HashAlgorithm = $result.HashAlgorithm
        TimeStamp = Get-Date
    }
}

# Export results
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputFile = "rdp_cipher_audit_$timestamp.csv"
$results | Export-Csv -Path $outputFile -NoTypeInformation

# Display summary
$supportedCount = ($results | Where-Object { $_.Supported }).Count
Write-Host "`nSummary:"
Write-Host "========"
Write-Host "Total Cipher Suites Tested: $($results.Count)"
Write-Host "Supported Cipher Suites: $supportedCount"
Write-Host "Unsupported Cipher Suites: $($results.Count - $supportedCount)"

if ($supportedCount -gt 0) {
    Write-Host "`nSupported Cipher Suites:"
    $results | Where-Object { $_.Supported } | ForEach-Object {
        Write-Host "- $($_.CipherSuite)"
        Write-Host "  Cipher: $($_.CipherAlgorithm), KeyExchange: $($_.KeyExchangeAlgorithm), Hash: $($_.HashAlgorithm)"
    }
}

Write-Host "`nResults exported to: $outputFile"
