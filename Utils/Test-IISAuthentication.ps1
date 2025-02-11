# Enable verbose output for authentication debugging
$VerbosePreference = 'Continue'

function Test-IISAuthentication {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url,
        
        [Parameter(Mandatory=$false)]
        [switch]$ShowHeaders,
        
        [Parameter(Mandatory=$false)]
        [switch]$ShowContent
    )
    
    Write-Verbose "Starting authentication test for URL: $Url"
    Write-Verbose "Current user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    
    # Get computer and domain info
    $computerName = $env:COMPUTERNAME
    $domain = $env:USERDOMAIN
    Write-Verbose "Computer Name: $computerName"
    Write-Verbose "Domain: $domain"
    
    # Parse URL for diagnostic info
    $uri = New-Object System.Uri($Url)
    Write-Verbose "Host being accessed: $($uri.Host)"
    Write-Verbose "Scheme: $($uri.Scheme)"
    
    # Test DNS resolution
    try {
        $dns = [System.Net.Dns]::GetHostEntry($uri.Host)
        Write-Verbose "DNS Resolution successful: $($dns.HostName) -> $($dns.AddressList[0])"
        
        # Check SPNs for the resolved hostname
        Write-Verbose "`nChecking SPNs for $($dns.HostName):"
        $spnOutput = setspn -L $($dns.HostName) 2>&1
        if ($spnOutput -match "no such SPN") {
            Write-Verbose "No SPNs found for $($dns.HostName)"
        } else {
            $spnOutput | ForEach-Object {
                Write-Verbose "  $_"
            }
        }
    }
    catch {
        Write-Verbose "DNS Resolution failed: $($_.Exception.Message)"
    }
    
    # Create and configure request
    try {
        Write-Verbose "`nInitiating web request..."
        $webRequest = [System.Net.HttpWebRequest]::Create($Url)
        $webRequest.UseDefaultCredentials = $true
        $webRequest.PreAuthenticate = $true
        $webRequest.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        $webRequest.AllowAutoRedirect = $false  # Disable redirects to see exact auth response
        
        Write-Verbose "Created web request with default network credentials"
        Write-Verbose "Authentication level: $($webRequest.AuthenticationLevel)"
        Write-Verbose "Credentials type: $($webRequest.Credentials.GetType().Name)"
        
        # Add Verbose Headers
        $webRequest.Headers.Add("X-Debug", "true")
        
        Write-Verbose "Sending request..."
        try {
            $response = $webRequest.GetResponse()
        }
        catch [System.Net.WebException] {
            $response = $_.Exception.Response
            Write-Verbose "`nExamining auth headers from failed request:"
            
            # Check WWW-Authenticate header
            if ($response.Headers["WWW-Authenticate"]) {
                Write-Verbose "WWW-Authenticate headers found:"
                $response.Headers["WWW-Authenticate"].Split(',') | ForEach-Object {
                    Write-Verbose "  $_"
                }
            }
            else {
                Write-Verbose "No WWW-Authenticate header present"
            }
            
            throw
        }
        
        Write-Verbose "`nResponse received successfully"
        Write-Verbose "HTTP Status Code: $([int]$response.StatusCode) - $($response.StatusDescription)"
        Write-Verbose "Authentication Type Used: $($response.AuthenticationType)"
        
        if ($ShowHeaders) {
            Write-Verbose "`nResponse Headers:"
            $response.Headers.AllKeys | ForEach-Object {
                Write-Verbose "  $_`: $($response.Headers[$_])"
            }
        }
        
        if ($ShowContent) {
            Write-Verbose "`nReading response content..."
            $stream = $response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $content = $reader.ReadToEnd()
            Write-Verbose "Content length: $($content.Length) characters"
            Write-Output $content
        }
        
        $response.Close()
        Write-Verbose "Connection closed successfully"
        return $true
    }
    catch [System.Net.WebException] {
        Write-Error "Authentication failed: $($_.Exception.Message)"
        Write-Verbose "Error Status: $($_.Exception.Status)"
        Write-Verbose "Error Response: $($_.Exception.Response)"
        
        if ($_.Exception.Response) {
            Write-Verbose "`nError Response Details:"
            Write-Verbose "Response Status Code: $([int]$_.Exception.Response.StatusCode)"
            Write-Verbose "Response Status Description: $($_.Exception.Response.StatusDescription)"
            
            Write-Verbose "`nResponse Headers:"
            $_.Exception.Response.Headers.AllKeys | ForEach-Object {
                Write-Verbose "  $_`: $($_.Exception.Response.Headers[$_])"
            }
        }
        return $false
    }
    catch {
        Write-Error "Unexpected error: $($_.Exception.Message)"
        Write-Verbose "Exception type: $($_.Exception.GetType().FullName)"
        Write-Verbose "Stack trace: $($_.Exception.StackTrace)"
        return $false
    }
}

# Execute the test
$url = $args[0]
if (-not $url) {
    Write-Error "Please provide a URL as a parameter"
    exit
}

# Run the authentication test
Test-IISAuthentication -Url $url -ShowHeaders:$true -ShowContent:$true
