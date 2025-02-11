function Check-VolumeFileSystem {
    [CmdletBinding()]
    param()

    $checkNumber = 9
    $checkName = "Volume File System Format"
    
    try {
        $volumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' }
        $nonNTFSVolumes = $volumes | Where-Object { $_.FileSystem -ne 'NTFS' }
        
        if ($nonNTFSVolumes) {
            $details = "Found volumes not using NTFS: " + ($nonNTFSVolumes | ForEach-Object { "$($_.DriveLetter): ($($_.FileSystem))" } | Join-String -Separator ', ')
            return @{
                CheckNumber = $checkNumber
                Name = $checkName
                Status = "WARNING"
                Details = $details
            }
        }
        
        return @{
            CheckNumber = $checkNumber
            Name = $checkName
            Status = "OK"
            Details = "All local volumes are using NTFS"
        }
    }
    catch {
        return @{
            CheckNumber = $checkNumber
            Name = $checkName
            Status = "WARNING"
            Details = "Error checking volume file systems: $_"
        }
    }
} 