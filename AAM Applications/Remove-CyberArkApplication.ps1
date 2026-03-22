<#
.SYNOPSIS
    Deletes an application from CyberArk.

.DESCRIPTION
    This script authenticates to CyberArk and deletes a specified application from the Vault.
    Displays application details before deletion and requires user confirmation.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g. https://pvwa.company.com)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER AppID
    The application name to delete.

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation. Use only for testing with self-signed certificates.

.EXAMPLE
    $cred = Get-Credential
    .\Remove-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com" `
        -Credential $cred `
        -AppID "MyApp"

.EXAMPLE
    # List applications first, then delete
    .\Get-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com"
    .\Remove-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppID,

    [Parameter(Mandatory = $false)]
    [switch]$DisableCertificateValidation,

    [Parameter(Mandatory = $true)]
    [string]$PVWAUrl,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the Authentication type (Default: cyberark)')]
    [ValidateSet('cyberark', 'ldap', 'radius')]
    [string]$AuthenticationType = 'cyberark',

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the RADIUS OTP')]
    [string]$OTP,

    [Parameter(Mandatory = $false, HelpMessage = 'Pass an existing psPAS session object. If passed the session is NOT logged off')]
    [Alias('session', 'sessionToken')]
    [object]$LogonToken
)

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )

    # Simple operator friendly logging
    Write-Output ("{0} {1}" -f $Level.ToUpper().PadRight(5), $Message)
}

# Initial state
$exitCode = 0
$shouldLogoff = $true
$app = $null

# Normalize URL once at the start
$PVWAUrl = $PVWAUrl.Trim().TrimEnd('/')
$AppID = $AppID.Trim()
if (-not [string]::IsNullOrWhiteSpace($OTP)) {
    $OTP = $OTP.Trim()
}

# Basic validation
if ([string]::IsNullOrWhiteSpace($AppID)) {
    Write-Log 'ERROR' 'AppID cannot be blank.'
    exit 1
}

if ([string]::IsNullOrWhiteSpace($PVWAUrl)) {
    Write-Log 'ERROR' 'PVWAUrl cannot be blank.'
    exit 1
}

# RADIUS requires OTP
if ($AuthenticationType -eq 'radius' -and [string]::IsNullOrWhiteSpace($OTP)) {
    Write-Log 'ERROR' 'OTP is required when AuthenticationType is radius.'
    exit 1
}

# Confirm psPAS is available before doing anything else
if (-not (Get-Module -ListAvailable -Name psPAS)) {
    Write-Log 'ERROR' 'psPAS module is not installed or not available.'
    exit 1
}

# Import psPAS into the current session
Import-Module psPAS -ErrorAction Stop

# Authentication / session handling
if ($null -ne $LogonToken) {
    # Reuse caller provided psPAS session
    try {
        Use-PASSession -Session $LogonToken
        $shouldLogoff = $false
        Write-Log 'INFO' 'Using provided psPAS session. Script will not log off.'
    } catch {
        Write-Log 'ERROR' ("Could not use provided psPAS session: {0}" -f $_.Exception.Message)
        exit 1
    }
} else {
    # Prompt if credential not supplied
    if (-not $Credential) {
        $Credential = Get-Credential -Message 'Enter CyberArk credentials'
    }

    if (-not $Credential) {
        Write-Log 'ERROR' 'Credentials are required to proceed.'
        exit 1
    }

    Write-Log 'INFO' ("Authenticating with psPAS using {0}..." -f $AuthenticationType)

    # Build New-PASSession parameters
    $sessionParams = @{
        BaseURI          = $PVWAUrl
        Credential       = $Credential
        Type             = $AuthenticationType
        SkipVersionCheck = $true
    }

    # Optional certificate validation bypass
    if ($DisableCertificateValidation) {
        $sessionParams['SkipCertificateCheck'] = $true
    }

    # Add OTP only for RADIUS
    if ($AuthenticationType -eq 'radius') {
        $sessionParams['OTP'] = $OTP
    }

    # Create a new psPAS session
    try {
        $null = New-PASSession @sessionParams
        Write-Log 'INFO' 'Authentication successful.'
    } catch {
        Write-Log 'ERROR' ("Authentication failed: {0}" -f $_.Exception.Message)
        exit 1
    }
}

# Retrieve application details before deletion
if ($exitCode -eq 0) {
    Write-Log 'INFO' ("Retrieving application details for '{0}'..." -f $AppID)

    try {
        $app = Get-PASApplication -AppID $AppID -ExactMatch
    } catch {
        $app = $null
        Write-Log 'ERROR' ("Could not retrieve application '{0}': {1}" -f $AppID, $_.Exception.Message)
        $exitCode = 1
    }

    if ($exitCode -eq 0 -and $null -eq $app) {
        Write-Log 'ERROR' ("Application '{0}' not found." -f $AppID)
        $exitCode = 1
    }
}

# Display application selected for deletion
if ($exitCode -eq 0) {
    Write-Output ''
    Write-Output 'Application to be deleted:'
    Write-Output ('=' * 80)
    Write-Output ("  AppID: {0}" -f $app.AppID)

    if ($app.Description) {
        Write-Output ("  Description: {0}" -f $app.Description)
    }

    if ($app.Location) {
        Write-Output ("  Location: {0}" -f $app.Location)
    }

    Write-Output ("  Disabled: {0}" -f $app.Disabled)

    if ($null -ne $app.AccessPermittedFrom -or $null -ne $app.AccessPermittedTo) {
        Write-Output ("  Access Hours: {0} - {1}" -f $app.AccessPermittedFrom, $app.AccessPermittedTo)
    }

    if ($app.ExpirationDate) {
        Write-Output ("  Expiration Date: {0}" -f $app.ExpirationDate)
    }

    if ($app.BusinessOwnerFName -or $app.BusinessOwnerLName) {
        Write-Output ("  Business Owner: {0} {1}" -f $app.BusinessOwnerFName, $app.BusinessOwnerLName)
    }

    if ($app.BusinessOwnerEmail) {
        Write-Output ("  Business Owner Email: {0}" -f $app.BusinessOwnerEmail)
    }

    if ($app.BusinessOwnerPhone) {
        Write-Output ("  Business Owner Phone: {0}" -f $app.BusinessOwnerPhone)
    }

    Write-Output ('=' * 80)
}

# Confirm deletion
if ($exitCode -eq 0) {
    $confirmation = Read-Host ("Are you sure you want to delete application '{0}'? Type yes to continue" -f $AppID)
    if ($confirmation -ne 'yes') {
        Write-Log 'WARN' 'Deletion cancelled by user.'
        exit 1
    }
}

# Delete application
if ($exitCode -eq 0) {
    Write-Log 'INFO' ("Deleting application '{0}'..." -f $AppID)

    try {
        $null = Remove-PASApplication -AppID $AppID -Confirm:$false
        Write-Log 'INFO' ("Application '{0}' deleted successfully." -f $AppID)
    } catch {
        Write-Log 'ERROR' ("Could not delete application '{0}': {1}" -f $AppID, $_.Exception.Message)
        $exitCode = 1
    }
}

# Verify deletion
if ($exitCode -eq 0) {
    Write-Log 'INFO' 'Verifying application was deleted...'

    try {
        $appCheck = Get-PASApplication -AppID $AppID -ExactMatch
    } catch {
        $appCheck = $null
    }

    if ($null -eq $appCheck) {
        Write-Log 'INFO' ("Confirmed: Application '{0}' no longer exists." -f $AppID)
    } else {
        Write-Log 'WARN' ("Application '{0}' still appears to exist." -f $AppID)
        $exitCode = 1
    }
}

# Log off if we created the session
if ($shouldLogoff) {
    try {
        Write-Log 'INFO' 'Logging off...'
        Close-PASSession
        Write-Log 'INFO' 'Session closed successfully.'
    } catch {
        Write-Log 'WARN' ("Could not close session properly: {0}" -f $_.Exception.Message)
    }
} else {
    Write-Log 'INFO' 'psPAS session was provided. Not logging off.'
}

# Clear sensitive variable references
$Credential = $null

exit $exitCode
