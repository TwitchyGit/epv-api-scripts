<#
.SYNOPSIS
    Demonstrates a complete CyberArk application management workflow with session token reuse.

.DESCRIPTION
    This script demonstrates a full workflow of CyberArk application management operations:
    - Creating an application
    - Adding authentication methods
    - Retrieving application details
    - (Optional) Exporting application to CSV
    - (Optional) Modifying CSV and importing as new application
    - (Optional) Showing both original and imported applications
    - Cleanup operations

    It also shows efficient session token reuse across multiple operations, which is more
    efficient than authenticating for each individual operation.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g. https://pvwa.company.com)

.PARAMETER AuthenticationType
    The authentication type: cyberark, ldap, or radius (Default: cyberark)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER OTP
    One-time password for RADIUS authentication.

.PARAMETER LogonToken
    Pre-existing session token to use. If provided, skips authentication step.

.PARAMETER Automated
    Run in automated mode without prompts. Assumes yes to export/import demo and yes to cleanup.

.EXAMPLE
    .\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com"

.EXAMPLE
    .\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com" -Automated

.EXAMPLE
    .\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com" -AuthenticationType ldap

.EXAMPLE
    $cred = Get-Credential
    .\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com" -Credential $cred

.EXAMPLE
    # Use existing token
    $token = (Invoke-RestMethod -Uri "https://pvwa.company.com/API/Auth/CyberArk/Logon" ...)
    .\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com" -LogonToken $token
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PVWAUrl,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [ValidateSet('cyberark', 'ldap', 'radius')]
    [string]$AuthenticationType = 'cyberark',

    [Parameter(Mandatory = $false)]
    [string]$OTP,

    [Parameter(Mandatory = $false)]
    [Alias('session', 'sessionToken')]
    [string]$LogonToken,

    [Parameter(Mandatory = $false)]
    [switch]$Automated
)

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )

    # Simple operator friendly logging
    Write-Output ("{0} {1}" -f $Level.ToUpper().PadRight(5), $Message)
}

function Convert-SecureStringToPlainText {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecureString
    )

    # Convert SecureString for API logon payload
    # BSTR is zeroed immediately after use
    $bstr = $null
    $plainText = $null

    try {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    } finally {
        if ($bstr) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    return $plainText
}

function ConvertTo-URL {
    param(
        [string]$Text
    )

    # Encode values for safe inclusion in URLs
    if (-not [string]::IsNullOrWhiteSpace($Text)) {
        return [URI]::EscapeDataString($Text)
    }

    return $Text
}

function Invoke-CyberArkRest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $false)]
        [string]$Body
    )

    # Wrapper for consistent REST behaviour and error handling
    if ([string]::IsNullOrWhiteSpace($Body)) {
        return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -ContentType 'application/json' -ErrorAction Stop
    } else {
        return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -Body $Body -ContentType 'application/json' -ErrorAction Stop
    }
}

function Invoke-ChildScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$Arguments
    )

    # Run child script and fail fast if it returns a non-zero exit code
    & $ScriptPath @Arguments
    $scriptExitCode = $LASTEXITCODE

    if ($null -ne $scriptExitCode -and $scriptExitCode -ne 0) {
        throw ("Child script failed with exit code {0}: {1}" -f $scriptExitCode, $ScriptPath)
    }
}

function Remove-AppAndAuthentications {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseUrl,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$AppID
    )

    # Remove all auth methods first, then remove the application
    $encodedAppID = ConvertTo-URL -Text $AppID
    $getAuthUrl = "{0}/WebServices/PIMServices.svc/Applications/{1}/Authentications/" -f $BaseUrl, $encodedAppID
    $deleteAppUrl = "{0}/WebServices/PIMServices.svc/Applications/{1}/" -f $BaseUrl, $encodedAppID

    Write-Log 'INFO' ("Cleaning up application: {0}" -f $AppID)

    $authMethods = $null

    try {
        $authMethods = Invoke-CyberArkRest -Method GET -Uri $getAuthUrl -Headers $Headers
    } catch {
        Write-Log 'WARN' ("Could not retrieve authentication methods for {0}: {1}" -f $AppID, $_.Exception.Message)
    }

    if ($authMethods -and $authMethods.authentication) {
        foreach ($auth in $authMethods.authentication) {
            $deleteAuthUrl = "{0}/WebServices/PIMServices.svc/Applications/{1}/Authentications/{2}/" -f $BaseUrl, $encodedAppID, $auth.authID
            Write-Log 'INFO' ("Removing authentication AuthID {0} from {1}..." -f $auth.authID, $AppID)
            $null = Invoke-CyberArkRest -Method DELETE -Uri $deleteAuthUrl -Headers $Headers
        }
    }

    $null = Invoke-CyberArkRest -Method DELETE -Uri $deleteAppUrl -Headers $Headers
    Write-Log 'INFO' ("Application deleted successfully: {0}" -f $AppID)
}

# -------------------------------------------------------------------
# Initial state
# -------------------------------------------------------------------
$exitCode = 0
$sessionToken = $null
$shouldLogoff = $true
$plainPassword = $null
$headers = @{}
$testAppID = $null
$importedAppID = $null
$exportPath = $null
$importPath = $null

# Normalize URL once at the start
$PVWAUrl = $PVWAUrl.Trim().TrimEnd('/')

# -------------------------------------------------------------------
# Basic validation
# -------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($PVWAUrl)) {
    Write-Log 'ERROR' 'PVWAUrl cannot be blank.'
    exit 1
}

if ($AuthenticationType -eq 'radius' -and [string]::IsNullOrWhiteSpace($OTP)) {
    Write-Log 'ERROR' 'OTP is required when AuthenticationType is radius.'
    exit 1
}

# Ensure TLS 1.2 is enabled without wiping other flags
if (([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12) -eq 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

Write-Output ('=' * 80)
Write-Output 'CyberArk Application Management - Workflow Demonstration'
Write-Output ('=' * 80)

try {
    # -------------------------------------------------------------------
    # Step 1: Authenticate once and reuse token
    # -------------------------------------------------------------------
    if (-not [string]::IsNullOrWhiteSpace($LogonToken)) {
        Write-Output ''
        Write-Output '[STEP 1] Using provided session token...'
        $sessionToken = $LogonToken.Trim()
        $shouldLogoff = $false
        Write-Output 'Session token accepted. Will NOT log off at end.'
        Write-Output '  Token will be reused for all subsequent operations...'
    } else {
        Write-Output ''
        Write-Output '[STEP 1] Authenticating to CyberArk...'

        if (-not $Credential) {
            $Credential = Get-Credential -Message 'Enter CyberArk credentials'
        }

        if (-not $Credential) {
            throw 'Credentials are required to proceed.'
        }

        $plainPassword = Convert-SecureStringToPlainText -SecureString $Credential.Password

        if ([string]::IsNullOrWhiteSpace($plainPassword)) {
            throw 'Password could not be extracted from credential object.'
        }

        $passwordToSend = $plainPassword
        if ($AuthenticationType -eq 'radius') {
            $passwordToSend = '{0},{1}' -f $plainPassword, $OTP.Trim()
        }

        # Do not log this body because it contains sensitive data
        $authBody = @{
            username          = $Credential.UserName
            password          = $passwordToSend
            concurrentSession = $true
        } | ConvertTo-Json

        $authUrl = "{0}/API/Auth/{1}/Logon" -f $PVWAUrl, $AuthenticationType
        $sessionToken = [string](Invoke-CyberArkRest -Method POST -Uri $authUrl -Body $authBody)
        $shouldLogoff = $true

        Write-Output 'Authentication successful. Session token obtained.'
        Write-Output '  Token will be reused for all subsequent operations...'
    }

    $headers = @{
        Authorization = $sessionToken
        'Content-Type' = 'application/json'
    }

    # Common child script arguments
    $commonArgs = @{
        PVWAUrl     = $PVWAUrl
        LogonToken  = $sessionToken
    }

    # -------------------------------------------------------------------
    # Step 2: List all applications
    # -------------------------------------------------------------------
    Write-Output ''
    Write-Output '[STEP 2] Retrieving all applications...'

    Invoke-ChildScript -ScriptPath "$PSScriptRoot\Get-CyberArkApplications.ps1" -Arguments $commonArgs
    Write-Output 'Applications retrieved successfully'

    # -------------------------------------------------------------------
    # Step 3: Create a test application
    # -------------------------------------------------------------------
    Write-Output ''
    Write-Output '[STEP 3] Creating test application...'

    $testAppID = "TestApp_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Write-Output ("  Creating application: {0}" -f $testAppID)

    $newAppArgs = @{
        PVWAUrl     = $PVWAUrl
        LogonToken  = $sessionToken
        AppID       = $testAppID
        Description = 'Test application created by workflow demonstration'
        Location    = '\'
    }

    Invoke-ChildScript -ScriptPath "$PSScriptRoot\New-CyberArkApplication.ps1" -Arguments $newAppArgs
    Write-Output 'Application created successfully'

    # -------------------------------------------------------------------
    # Step 4: Add authentication methods
    # -------------------------------------------------------------------
    Write-Output ''
    Write-Output '[STEP 4] Adding authentication methods...'

    Write-Output ("  Adding Path authentication to {0}" -f $testAppID)
    Invoke-ChildScript -ScriptPath "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" -Arguments @{
        PVWAUrl    = $PVWAUrl
        LogonToken = $sessionToken
        AppID      = $testAppID
        Path       = 'C:\Program Files\TestApp\test.exe'
    }

    Write-Output ("  Adding OSUser authentication to {0}" -f $testAppID)
    Invoke-ChildScript -ScriptPath "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" -Arguments @{
        PVWAUrl    = $PVWAUrl
        LogonToken = $sessionToken
        AppID      = $testAppID
        OSUser     = 'DOMAIN\AppUser'
    }

    Write-Output ("  Adding MachineAddress authentication to {0}" -f $testAppID)
    Invoke-ChildScript -ScriptPath "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" -Arguments @{
        PVWAUrl         = $PVWAUrl
        LogonToken      = $sessionToken
        AppID           = $testAppID
        MachineAddress  = '192.168.1.100'
    }

    Write-Output ("  Adding Hash authentication to {0}" -f $testAppID)
    Invoke-ChildScript -ScriptPath "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" -Arguments @{
        PVWAUrl    = $PVWAUrl
        LogonToken = $sessionToken
        AppID      = $testAppID
        Hash       = 'ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890'
    }

    Write-Output ("  Adding Certificate Serial Number authentication to {0}" -f $testAppID)
    Invoke-ChildScript -ScriptPath "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" -Arguments @{
        PVWAUrl                  = $PVWAUrl
        LogonToken               = $sessionToken
        AppID                    = $testAppID
        CertificateSerialNumber  = '1234567890ABCDEF'
    }

    Write-Output ("  Adding Certificate Subject authentication to {0}" -f $testAppID)
    Invoke-ChildScript -ScriptPath "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" -Arguments @{
        PVWAUrl             = $PVWAUrl
        LogonToken          = $sessionToken
        AppID               = $testAppID
        CertificateSubject  = @('CN=TestApp', 'OU=IT', 'O=Company', 'C=US')
    }

    Write-Output ("  Adding Certificate Issuer authentication to {0}" -f $testAppID)
    Invoke-ChildScript -ScriptPath "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" -Arguments @{
        PVWAUrl             = $PVWAUrl
        LogonToken          = $sessionToken
        AppID               = $testAppID
        CertificateIssuer   = @('CN=Company Root CA', 'OU=Security')
    }

    Write-Output ("  Adding Certificate Subject Alternative Name authentication to {0}" -f $testAppID)
    Invoke-ChildScript -ScriptPath "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" -Arguments @{
        PVWAUrl                            = $PVWAUrl
        LogonToken                         = $sessionToken
        AppID                              = $testAppID
        CertificateSubjectAlternativeName  = @('DNS Name=testapp.company.com', 'DNS Name=testapp.local')
    }

    Write-Output 'Authentication methods added successfully'

    # -------------------------------------------------------------------
    # Step 5: Retrieve authentication methods
    # -------------------------------------------------------------------
    Write-Output ''
    Write-Output '[STEP 5] Retrieving authentication methods...'

    Invoke-ChildScript -ScriptPath "$PSScriptRoot\Get-CyberArkAppAuthentication.ps1" -Arguments @{
        PVWAUrl    = $PVWAUrl
        LogonToken = $sessionToken
        AppID      = $testAppID
    }

    Write-Output 'Authentication methods retrieved successfully'

    # -------------------------------------------------------------------
    # Step 6: Optional export/import demo
    # -------------------------------------------------------------------
    Write-Output ''
    Write-Output '[STEP 6] Export/Import demonstration...'

    if ($Automated) {
        $demoExportImport = 'yes'
        Write-Output 'Automated mode: Running export/import demo'
    } else {
        $demoExportImport = Read-Host 'Do you want to demo Export/Import functionality? (yes/no)'
    }

    if ($demoExportImport -eq 'yes') {
        # Step 6a: Export application
        Write-Output ''
        Write-Output '  [STEP 6a] Exporting application to CSV...'

        $exportPath = Join-Path -Path $PSScriptRoot -ChildPath ("export_{0}.csv" -f $testAppID)
        Write-Output ("    Exporting {0} to: {1}" -f $testAppID, $exportPath)

        Invoke-ChildScript -ScriptPath "$PSScriptRoot\Export-CyberArkApplications.ps1" -Arguments @{
            PVWAUrl    = $PVWAUrl
            LogonToken = $sessionToken
            AppID      = $testAppID
            CSVPath    = $exportPath
        }

        Write-Output '    Application exported successfully'

        # Step 6b: Modify CSV for import
        Write-Output ''
        Write-Output '  [STEP 6b] Modifying CSV for import...'

        $exportedData = Import-Csv -Path $exportPath
        if (-not $exportedData) {
            throw 'Exported CSV did not contain any rows.'
        }

        $importedAppID = "{0}_Imported" -f $exportedData[0].AppID

        foreach ($row in $exportedData) {
            $row.AppID = $importedAppID
            $row.Description = "{0} (Imported copy from {1})" -f $row.Description, $testAppID
        }

        Write-Output ("    Original AppID: {0}" -f $testAppID)
        Write-Output ("    New AppID: {0}" -f $importedAppID)

        $importPath = Join-Path -Path $PSScriptRoot -ChildPath ("import_{0}.csv" -f $testAppID)
        $exportedData | Export-Csv -Path $importPath -NoTypeInformation -Encoding UTF8
        Write-Output ("    Modified CSV saved to: {0}" -f $importPath)

        # Step 6c: Import application
        Write-Output ''
        Write-Output '  [STEP 6c] Importing application from CSV...'

        Invoke-ChildScript -ScriptPath "$PSScriptRoot\Import-CyberArkApplications.ps1" -Arguments @{
            PVWAUrl    = $PVWAUrl
            LogonToken = $sessionToken
            CSVPath    = $importPath
        }

        Write-Output '    Application imported successfully'

        # Step 6d: Show applications
        Write-Output ''
        Write-Output '  [STEP 6d] Listing all applications (showing both original and imported)...'

        Invoke-ChildScript -ScriptPath "$PSScriptRoot\Get-CyberArkApplications.ps1" -Arguments $commonArgs

        Write-Output ''
        Write-Output '    Both applications now exist:'
        Write-Output ("      - Original: {0}" -f $testAppID)
        Write-Output ("      - Imported: {0}" -f $importedAppID)

        # Step 6e: Show original auth methods
        Write-Output ''
        Write-Output ("  [STEP 6e] Authentication methods for ORIGINAL application ({0})..." -f $testAppID)

        Invoke-ChildScript -ScriptPath "$PSScriptRoot\Get-CyberArkAppAuthentication.ps1" -Arguments @{
            PVWAUrl    = $PVWAUrl
            LogonToken = $sessionToken
            AppID      = $testAppID
        }

        # Step 6f: Show imported auth methods
        Write-Output ''
        Write-Output ("  [STEP 6f] Authentication methods for IMPORTED application ({0})..." -f $importedAppID)

        Invoke-ChildScript -ScriptPath "$PSScriptRoot\Get-CyberArkAppAuthentication.ps1" -Arguments @{
            PVWAUrl    = $PVWAUrl
            LogonToken = $sessionToken
            AppID      = $importedAppID
        }

        # Clean up import CSV
        if (Test-Path -LiteralPath $importPath) {
            Remove-Item -LiteralPath $importPath -Force
            Write-Output ''
            Write-Output '    Import CSV cleaned up'
        }
    } else {
        Write-Output '  Export/Import demo skipped'
    }

    # -------------------------------------------------------------------
    # Step 7: Cleanup applications
    # -------------------------------------------------------------------
    Write-Output ''
    Write-Output '[STEP 7] Cleanup...'

    if ($Automated) {
        $cleanup = 'yes'
        Write-Output 'Automated mode: Cleaning up test applications'
    } else {
        $cleanup = Read-Host 'Do you want to delete the test application(s)? (yes/no)'
    }

    if ($cleanup -eq 'yes') {
        if (-not [string]::IsNullOrWhiteSpace($testAppID)) {
            Remove-AppAndAuthentications -BaseUrl $PVWAUrl -Headers $headers -AppID $testAppID
        }

        if (-not [string]::IsNullOrWhiteSpace($importedAppID)) {
            try {
                Remove-AppAndAuthentications -BaseUrl $PVWAUrl -Headers $headers -AppID $importedAppID
            } catch {
                Write-Log 'WARN' ("Could not delete imported application {0}: {1}" -f $importedAppID, $_.Exception.Message)
            }
        }

        Write-Output ''
        Write-Output '  All test applications cleaned up'
    } else {
        Write-Output '  Test application(s) were NOT deleted:'
        if ($testAppID) {
            Write-Output ("    - {0}" -f $testAppID)
        }
        if ($importedAppID) {
            Write-Output ("    - {0}" -f $importedAppID)
        }
    }

    # -------------------------------------------------------------------
    # Step 8: Export file cleanup
    # -------------------------------------------------------------------
    if ($exportPath -and (Test-Path -LiteralPath $exportPath)) {
        if ($Automated) {
            Write-Output ''
            Write-Output ("Automated mode: Keeping export file for inspection at: {0}" -f $exportPath)
        } else {
            $cleanupExport = Read-Host 'Do you want to delete the export file? (yes/no)'
            if ($cleanupExport -eq 'yes') {
                Remove-Item -LiteralPath $exportPath -Force
                Write-Output '  Export file deleted'
            } else {
                Write-Output ("  Export file kept at: {0}" -f $exportPath)
            }
        }
    }

    # -------------------------------------------------------------------
    # Step 9: Manual logoff
    # -------------------------------------------------------------------
    if ($shouldLogoff) {
        Write-Output ''
        Write-Output '[STEP 9] Logging off...'
        $logoffUrl = "{0}/API/Auth/Logoff" -f $PVWAUrl
        $null = Invoke-CyberArkRest -Method POST -Uri $logoffUrl -Headers @{ Authorization = $sessionToken }
        Write-Output 'Session closed successfully'
    } else {
        Write-Output ''
        Write-Output '[STEP 9] Skipping logoff (token was provided externally)...'
        Write-Output '  External caller is responsible for session management'
    }

    # -------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------
    Write-Output ''
    Write-Output ('=' * 80)
    Write-Output 'SUMMARY:'
    Write-Output ('=' * 80)

    if ($LogonToken) {
        Write-Output 'Used EXISTING session token (provided as parameter)'
        Write-Output 'Token reused across MULTIPLE script operations'
        Write-Output 'Session NOT logged off (external token management)'
    } else {
        Write-Output 'Authenticated ONCE and obtained session token'
        Write-Output 'Used token across MULTIPLE script operations'
        Write-Output 'No logoff occurred during child script calls'
        if ($shouldLogoff) {
            Write-Output 'Manually logged off when all operations completed'
        }
    }

    Write-Output ''
    Write-Output 'This demonstrates efficient session token reuse!'
    Write-Output ('=' * 80)
} catch {
    $exitCode = 1
    Write-Output ''
    Write-Log 'ERROR' ("Workflow failed: {0}" -f $_.Exception.Message)

    if ($_.ErrorDetails.Message) {
        Write-Log 'ERROR' ("API Error Details: {0}" -f $_.ErrorDetails.Message)
    }

    # Attempt logoff only if this script created the session
    if ($sessionToken -and $shouldLogoff) {
        try {
            Write-Output ''
            Write-Output 'Attempting to log off...'
            $logoffUrl = "{0}/API/Auth/Logoff" -f $PVWAUrl
            $null = Invoke-CyberArkRest -Method POST -Uri $logoffUrl -Headers @{ Authorization = $sessionToken }
            Write-Output 'Session closed.'
        } catch {
            Write-Output 'Could not close session properly.'
        }
    } elseif (-not $shouldLogoff) {
        Write-Output ''
        Write-Output 'Session token was provided externally. Not logging off.'
    }
} finally {
    # Clear sensitive variable references
    $plainPassword = $null
    $Credential = $null
}

if ($exitCode -eq 0) {
    Write-Output ''
    Write-Output 'Example completed successfully!'
}

exit $exitCode
