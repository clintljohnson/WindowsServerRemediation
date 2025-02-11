function Write-Report {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$Results,
        
        [Parameter()]
        [switch]$ShowWarningsOnly,
        
        [Parameter()]
        [string]$OutputPath
    )
    
    # Create reports directory if it doesn't exist
    $reportsDir = Join-Path $PSScriptRoot "..\..\reports"
    if (-not (Test-Path $reportsDir)) {
        Write-Verbose "Creating reports directory: $reportsDir"
        New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null
    }
    
    # Sort results by CheckNumber (ensuring proper numerical sorting)
    $Results = $Results | Sort-Object { [int]$_.CheckNumber } | ForEach-Object {
        # Ensure CheckNumber is properly formatted as a string
        $_.CheckNumber = [string]([int]$_.CheckNumber)
        $_
    }
    
    # If ShowWarningsOnly is true, filter for warnings
    $warningResults = if ($ShowWarningsOnly) {
        $Results | Where-Object { $_.Status -eq "WARNING" }
    } else {
        $Results
    }

    # If showing warnings only and none found, display message and return
    if ($ShowWarningsOnly -and -not $warningResults) {
        Write-Host "`nNo WARNINGS found.`n"
        return
    }
    
    # Function to create a table border
    function Get-TableBorder {
        return "+{0}+{1}+{2}+{3}+" -f ('-' * 5), ('-' * 44), ('-' * 10), ('-' * 148)
    }

    # Function to format a table row
    function Format-TableRow {
        param(
            [string]$RefNum,
            [string]$Check,
            [string]$Status,
            [string]$Details
        )
        # Convert PASS to OK
        if ($Status -eq "PASS") { $Status = "OK" }
        
        # Format the reference number with appropriate leading spaces
        $refPadded = if ($RefNum -eq "Ref") {
            $RefNum.PadRight(2)
        } else {
            $num = [int]$RefNum
            if ($num -lt 10) {
                "  $num"  # Two leading spaces for single digits
            } elseif ($num -lt 100) {
                " $num"   # One leading space for double digits
            } else {
                "$num"    # No leading space for triple digits
            }
        }
        
        $checkPadded = $Check.PadRight(42).Substring(0, 42)
        $statusPadded = $Status.PadRight(8).Substring(0, 8)
        $detailsPadded = $Details.PadRight(146).Substring(0, 146)
        
        return "| $refPadded | $checkPadded | $statusPadded | $detailsPadded |"
    }
    
    # Display results table
    Write-Host (Get-TableBorder)
    Write-Host (Format-TableRow -RefNum "Ref" -Check "Check" -Status "Status" -Details "Details")
    Write-Host (Get-TableBorder)

    # Track seen check numbers to prevent duplicates
    $seenCheckNumbers = @{}

    foreach ($result in $warningResults) {
        # Skip if we've already seen this check number
        if ($seenCheckNumbers.ContainsKey($result.CheckNumber)) {
            Write-Verbose "Skipping duplicate check number: $($result.CheckNumber)"
            continue
        }
        
        # Record that we've seen this check number
        $seenCheckNumbers[$result.CheckNumber] = $true

        # Convert PASS to OK in the result object for CSV export
        if ($result.Status -eq "PASS") { $result.Status = "OK" }
        
        Write-Host (Format-TableRow -RefNum $result.CheckNumber `
                                  -Check $result.Name `
                                  -Status $result.Status `
                                  -Details $result.Details)
    }

    Write-Host (Get-TableBorder)
    
    # Export to CSV if path provided
    if ($OutputPath) {
        # Always use reports directory, but keep the filename from OutputPath if provided
        $date = Get-Date -Format "yyyyMMdd_HHmmss"
        $computerName = $env:COMPUTERNAME
        
        if ($OutputPath -eq ".\SecurityReport.csv" -or [string]::IsNullOrEmpty($filename)) {
            $filename = "SecurityReport_${computerName}_${date}.csv"
        } else {
            # Get filename without extension
            $filenameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
            $extension = [System.IO.Path]::GetExtension($OutputPath)
            if ([string]::IsNullOrEmpty($extension)) {
                $extension = ".csv"
            }
            $filename = "${filenameNoExt}_${computerName}_${date}${extension}"
        }
        
        $finalPath = Join-Path $reportsDir $filename
        Write-Verbose "Exporting results to CSV file: $finalPath"
        $Results | Export-Csv -Path $finalPath -NoTypeInformation
        Write-Host "`nReport saved to: reports\$filename"
    }
} 