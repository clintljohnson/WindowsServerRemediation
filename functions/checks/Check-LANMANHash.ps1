function Check-LANMANHash {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    $result = @{
        CheckNumber = 22
        Name = "LANMAN Hash Status"
        Status = "OK"
        Details = "LANMAN hash generation is properly disabled"
    }

    try {
        Write-Verbose "Checking LANMAN hash settings on $ComputerName"

        $checkResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $regName = "NoLMHash"
            
            try {
                $value = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
                return @{
                    Exists = $true
                    Value = $value.NoLMHash
                }
            }
            catch {
                return @{
                    Exists = $false
                    Value = $null
                }
            }
        }

        if (-not $checkResult.Exists -or $checkResult.Value -ne 1) {
            $result.Status = "WARNING"
            $result.Details = if (-not $checkResult.Exists) {
                "LANMAN hash setting is not configured"
            } else {
                "LANMAN hash generation is not disabled (current value: $($checkResult.Value))"
            }
        }
    }
    catch {
        $result.Status = "WARNING"
        $result.Details = "Error checking LANMAN hash settings on $ComputerName`: $_"
    }

    return $result
} 