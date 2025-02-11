# Windows Server Remediation

A comprehensive PowerShell-based security assessment and remediation tool for Windows Server 2022 and 2025.

## Overview

This tool performs automated security checks and optional remediation for Windows Server environments, focusing on industry best practices and security hardening guidelines. It can process multiple servers simultaneously and generates detailed reports of findings.

## Key Features

- 45+ security checks covering:
  - System Updates and Patches
  - User Rights and Permissions
  - Registry Security
  - Service Configurations
  - Network Security
  - Authentication Protocols
  - Encryption Standards
  - Remote Access Settings
  - File System Security
  - Password Policies
  - Account Security
  - Audit Settings
  - Protocol Security (SMB, RDP, TLS)

- Automated remediation capabilities
- Detailed CSV reporting
- Remote server support
- Verbose logging options
- Selective check execution
- Batch processing support

## Prerequisites

- PowerShell 5.1 or higher
- WinRM enabled on target servers
- Administrative privileges on target servers
- Network connectivity to target servers

## Installation

1. Clone the repository:
```bash
git clone https://github.com/clintljohnson/WindowsServerRemediation.git
```

2. Navigate to the project directory:
```bash
cd windows-server-remediation
```

## Usage

### Basic Syntax

```powershell
.\ServerSecurityCheck.ps1 -TargetServers <server1,server2,...> [-ShowWarningsOnly] [-FixWarnings] [-OutputPath <path>] [-Verbose]
```

### Parameters

- `-TargetServers`: Required. Comma-separated list of servers or path to a file containing server names
- `-ShowWarningsOnly`: Optional. Only display checks that resulted in warnings
- `-FixWarnings`: Optional. Prompt to fix any warnings that are found
- `-OutputPath`: Optional. Path to save the CSV report (Default: .\SecurityReport.csv)
- `-SkipChecks`: Optional. Comma-separated list of check numbers to skip
- `-CheckOnly`: Optional. Comma-separated list of check numbers to run exclusively
- `-Force`: Optional. Automatically answer yes to all fix prompts
- `-Verbose`: Optional. Show detailed progress information

### Examples

```powershell

# Get usage instructions
.\ServerSecurityCheck.ps1

# Check single server
.\ServerSecurityCheck.ps1 -TargetServers "SERVER01"

# Check multiple servers
.\ServerSecurityCheck.ps1 -TargetServers "SERVER01","SERVER02","SERVER03"

# Check and fix warnings one at awith confirmation prompts
.\ServerSecurityCheck.ps1 -TargetServers "SERVER01" -FixWarnings

# Check and fix warnings with automatic confirmation (Carefull!)
.\ServerSecurityCheck.ps1 -TargetServers "SERVER01" -FixWarnings -Force

# Check servers listed in a file
.\ServerSecurityCheck.ps1 -TargetServers (Get-Content servers.txt)

# Run specific checks only
.\ServerSecurityCheck.ps1 -TargetServers "SERVER01" -CheckOnly "1,2,3"

# Skip specific checks
.\ServerSecurityCheck.ps1 -TargetServers "SERVER01" -SkipChecks "4,5,6"
```

## Security Checks

The tool performs checks in several key areas:

1. System Security
   - Service pack and patch status
   - Operating system rights
   - Debug program permissions
   - Installer privileges

2. Network Security
   - Remote registry access
   - Remote assistance settings
   - SMB protocol security
   - RDP security configuration
   - TCP/IP security

3. Authentication & Access
   - Account lockout settings
   - Password policies
   - Guest account status
   - Anonymous access
   - NTLM settings

4. Encryption & Protocols
   - TLS configuration
   - Cipher suites
   - Protocol security
   - Certificate validation

5. System Services
   - Unnecessary services
   - Service account permissions
   - SNMP security
   - Event log settings

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the GNU General Public License v3.0 - see the [gpl-3.0.txt](gpl-3.0.txt) file for details.

## Disclaimer

⚠️ **WARNING**: While this tool has been tested in various environments, it makes significant system changes when remediation is enabled. Always:

1. Test in a non-production environment first
2. Back up your systems before running remediation
3. Review the proposed changes before applying them
4. Use at your own risk

The authors and contributors are not responsible for any damage or data loss that may occur from using this tool.
