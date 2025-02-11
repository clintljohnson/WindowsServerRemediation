function Fix-VolumeFileSystem {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting fix operation for VolumeFileSystem on $ComputerName"

    try {
        # First check current state
        $currentState = Check-VolumeFileSystem -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - all volumes are already NTFS"
            return $true
        }

        # Since this is a manual operation, provide detailed guidance
        Write-Warning "Converting volumes to NTFS requires backing up data and reformatting. This cannot be automated safely."
        Write-Host "`nThe following volumes need attention:" -ForegroundColor Yellow
        
        $nonNTFSVolumes = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.FileSystem -ne 'NTFS' }
        }

        foreach ($volume in $nonNTFSVolumes) {
            Write-Host "- Drive ${volume.DriveLetter}: (Current format: $($volume.FileSystem))" -ForegroundColor Yellow
        }

        Write-Host "`nPlease follow these manual steps for each non-NTFS volume:" -ForegroundColor Cyan
        Write-Host "1. Back up all data from the volume"
        Write-Host "2. Use 'convert <drive>: /fs:ntfs' command"
        Write-Host "   OR"
        Write-Host "3. Format the volume as NTFS using Disk Management"
        Write-Host "`nAfter completing these steps, run the security check again to verify." -ForegroundColor Green
        
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 