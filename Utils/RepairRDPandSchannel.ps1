Invoke-Command -ComputerName HSDIV -ScriptBlock {
    # Reset TLS cipher suite order to Windows defaults
    $defaultCipherOrder = @(
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
    )

    foreach ($cipher in $defaultCipherOrder) {
        Enable-TlsCipherSuite -Name $cipher
    }

    # Reset and configure key container permissions
    $keyPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
    $acl = Get-Acl $keyPath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT SERVICE\TermService",
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($rule)
    Set-Acl $keyPath $acl

    # Restart key services
    $services = @(
        "KeyIso",          # CNG Key Isolation
        "TermService",     # Remote Desktop Services
        "UmRdpService"     # Remote Desktop Services UserMode Port Redirector
    )

    foreach ($service in $services) {
        Write-Host "Restarting $service..."
        Restart-Service -Name $service -Force
        Start-Sleep -Seconds 2
    }

    # Verify cipher suite configuration
    Write-Host "`nCurrent TLS Cipher Suites:"
    Get-TlsCipherSuite | Where-Object {$_.Name -like "TLS_ECDHE*"} | Format-Table Name, Certificate

    # Check certificate store
    Write-Host "`nCurrent RDP Certificates:"
    Get-ChildItem "Cert:\LocalMachine\Remote Desktop" -ErrorAction SilentlyContinue | 
        Format-Table Subject, Thumbprint, NotAfter

    # Verify TLS registry settings
    Write-Host "`nTLS 1.2 Configuration:"
    @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
    ) | ForEach-Object {
        if (Test-Path $_) {
            Get-ItemProperty $_ -Name "Enabled", "DisabledByDefault" -ErrorAction SilentlyContinue
        }
    }

    # Check for recent SChannel errors after restart
    Write-Host "`nChecking for new SChannel errors..."
    Start-Sleep -Seconds 5
    Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        StartTime = (Get-Date).AddMinutes(-2)
        ID = 36871
    } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message
}
