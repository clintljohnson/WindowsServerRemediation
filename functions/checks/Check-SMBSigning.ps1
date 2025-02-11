function Check-SMBSigning {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 29
        Name = "SMB Signing Configuration"
        Status = "OK"
        Details = "SMB signing is properly configured and required"
    }

    try {
        $smbConfig = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-SmbServerConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature
        }

        Write-Verbose "SMB Configuration: EnableSecuritySignature=$($smbConfig.EnableSecuritySignature), RequireSecuritySignature=$($smbConfig.RequireSecuritySignature)"

        if (-not $smbConfig.EnableSecuritySignature -or -not $smbConfig.RequireSecuritySignature) {
            $result.Status = "WARNING"
            $result.Details = "SMB signing is not properly configured. " +
                            "EnableSecuritySignature=$($smbConfig.EnableSecuritySignature), " +
                            "RequireSecuritySignature=$($smbConfig.RequireSecuritySignature). " +
                            "Both settings should be enabled for optimal security."
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking SMB signing configuration: $_"
    }

    return $result
} 