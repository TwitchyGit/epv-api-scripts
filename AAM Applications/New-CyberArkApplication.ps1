<#
.SYNOPSIS
    Adds a new application to CyberArk using psPAS.

.DESCRIPTION
    This script authenticates with psPAS and creates a new application in the Vault.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g. https://pvwa.company.com or https://pvwa.company.com/PasswordVault)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER AppID
    The application name (required).

.PARAMETER Description
    Optional description of the application.

.PARAMETER Location
    Optional location of the application in the Vault hierarchy.
    If not supplied, "\" will be used.

.PARAMETER AccessPermittedFrom
    Optional start hour that access is permitted (0-23).

.PARAMETER AccessPermittedTo
    Optional end hour that access is permitted (0-23).

.PARAMETER ExpirationDate
    Optional expiration date of the application in mm-dd-yyyy format.

.PARAMETER Disabled
    Optional flag to create the application as disabled. Default is $false.

.PARAMETER BusinessOwnerFName
    Optional business owner first name.

.PARAMETER BusinessOwnerLName
    Optional business owner last name.

.PARAMETER BusinessOwnerEmail
    Optional business owner email.

.PARAMETER BusinessOwnerPhone
    Optional business owner phone number.

.PARAMETER DisableCertificateValidation
    Skips certificate checks in New-PASSession. Use only for testing.

.PARAMETER AuthenticationType
    Authentication type for New-PASSession: cyberark, ldap, or radius.

.PARAMETER OTP
    OTP for RADIUS authentication.

.PARAMETER LogonToken
    Existing psPAS session object from Get-PASSession / New-PASSession.
    If provided, the script will reuse it and will NOT log off.

.EXAMPLE
    $cred = Get-Credential
    .\New-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com/PasswordVault" `
        -Credential $cred `
        -AppID "MyNewApp" `
        -Description "My application for testing" `
        -Location "\Applications"

.EXAMPLE
    .\New-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com/PasswordVault" `
        -AppID "MyNewApp" `
        -BusinessOwnerFName "John" `
        -BusinessOwnerLName "Doe" `
        -BusinessOwnerEmail "john.doe@company.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppID,

    [Parameter(Mandatory = $false)]
    [string]$Description,

    [Parameter(Mandatory = $false)]
    [string]$Location,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 23)]
    [int]$AccessPermittedFrom,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 23)]
    [int]$AccessPermittedTo,

    [Parameter(Mandatory = $false)]
    [string]$ExpirationDate,

    [Parameter(Mandatory = $false)]
    [bool]$Disabled = $false,

    [Parameter(Mandatory = $false)]
    [string]$BusinessOwnerFName,

    [Parameter(Mandatory = $false)]
    [string]$BusinessOwnerLName,

    [Parameter(Mandatory = $false)]
    [string]$BusinessOwnerEmail,

    [Parameter(Mandatory = $false)]
    [string]$BusinessOwnerPhone,

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

    Write-Output ("{0} {1}" -f $Level.ToUpper().PadRight(5), $Message)
}

$exitCode = 0
$shouldLogoff = $true
$parsedExpirationDate = $null
$targetLocation = $null

$PVWAUrl = $PVWAUrl.Trim().TrimEnd('/')
$AppID = $AppID.Trim()

if (-not [string]::IsNullOrWhiteSpace($Location)) {
    $Location = $Location.Trim()
}

if (-not [string]::IsNullOrWhiteSpace($OTP)) {
    $OTP = $OTP.Trim()
}

if ([string]::IsNullOrWhiteSpace($AppID)) {
    Write-Log 'ERROR' 'AppID cannot be blank.'
    exit 1
}

if ([string]::IsNullOrWhiteSpace($PVWAUrl)) {
    Write-Log 'ERROR' 'PVWAUrl cannot be blank.'
    exit 1
}

if ($AuthenticationType -eq 'radius' -and [string]::IsNullOrWhiteSpace($OTP)) {
    Write-Log 'ERROR' 'OTP is required when AuthenticationType is radius.'
    exit 1
}

if (-not [string]::IsNullOrWhiteSpace($ExpirationDate)) {
    if (-not [datetime]::TryParseExact($ExpirationDate, 'MM-dd-yyyy', $null, [System.Globalization.DateTimeStyles]::None, [ref]$parsedExpirationDate)) {
        Write-Log 'ERROR' 'ExpirationDate must be in MM-dd-yyyy format.'
        exit 1
    }
}

$targetLocation = '\'
if (-not [string]::IsNullOrWhiteSpace($Location)) {
    $targetLocation = $Location
}

if (-not (Get-Module -ListAvailable -Name psPAS)) {
    Write-Log 'ERROR' 'psPAS module is not installed or not available.'
    exit 1
}

Import-Module psPAS -ErrorAction Stop

try {
    if ($null -ne $LogonToken) {
        if ($LogonToken -is [string]) {
            Write-Log 'ERROR' 'For psPAS, LogonToken must be a psPAS session object from Get-PASSession, not a raw token string.'
            exit 1
        }

        Use-PASSession -Session $LogonToken
        $shouldLogoff = $false
        Write-Log 'INFO' 'Using provided psPAS session. Script will not log off.'
    } else {
        if (-not $Credential) {
            $Credential = Get-Credential -Message 'Enter CyberArk credentials'
        }

        if (-not $Credential) {
            Write-Log 'ERROR' 'Credentials are required to proceed.'
            exit 1
        }

        Write-Log 'INFO' ("Authenticating with psPAS using {0}..." -f $AuthenticationType)

        $sessionParams = @{
            BaseURI          = $PVWAUrl
            Credential       = $Credential
            Type             = $AuthenticationType
            SkipVersionCheck = $true
        }

        if ($DisableCertificateValidation) {
            $sessionParams['SkipCertificateCheck'] = $true
        }

        if ($AuthenticationType -eq 'radius' -and -not [string]::IsNullOrWhiteSpace($OTP)) {
            $sessionParams['OTP'] = $OTP
        }

        $null = New-PASSession @sessionParams
        Write-Log 'INFO' 'Authentication successful.'
    }

    Write-Log 'INFO' ("Checking if application '{0}' already exists..." -f $AppID)

    $existingApp = $null
    try {
        $existingApp = Get-PASApplication -Search $AppID
    } catch {
        $existingApp = $null
    }

    $appExists = $false
    if ($existingApp) {
        $matchingApps = @($existingApp | Where-Object { $_.AppID -eq $AppID })
        if ($matchingApps.Count -gt 0) {
            $appExists = $true
        }
    }

    if ($appExists) {
        Write-Log 'ERROR' ("Application '{0}' already exists. Use a different name or delete the existing application first." -f $AppID)
        $exitCode = 1
    }

    if ($exitCode -eq 0) {
        $addParams = @{
            AppID    = $AppID
            Location = $targetLocation
            Disabled = $Disabled
        }

        if (-not [string]::IsNullOrWhiteSpace($Description)) { $addParams['Description'] = $Description.Trim() }
        if ($PSBoundParameters.ContainsKey('AccessPermittedFrom')) { $addParams['AccessPermittedFrom'] = $AccessPermittedFrom }
        if ($PSBoundParameters.ContainsKey('AccessPermittedTo')) { $addParams['AccessPermittedTo'] = $AccessPermittedTo }
        if ($null -ne $parsedExpirationDate) { $addParams['ExpirationDate'] = $parsedExpirationDate }
        if (-not [string]::IsNullOrWhiteSpace($BusinessOwnerFName)) { $addParams['BusinessOwnerFName'] = $BusinessOwnerFName.Trim() }
        if (-not [string]::IsNullOrWhiteSpace($BusinessOwnerLName)) { $addParams['BusinessOwnerLName'] = $BusinessOwnerLName.Trim() }
        if (-not [string]::IsNullOrWhiteSpace($BusinessOwnerEmail)) { $addParams['BusinessOwnerEmail'] = $BusinessOwnerEmail.Trim() }
        if (-not [string]::IsNullOrWhiteSpace($BusinessOwnerPhone)) { $addParams['BusinessOwnerPhone'] = $BusinessOwnerPhone.Trim() }

        Write-Log 'INFO' ("Creating application '{0}'..." -f $AppID)
        $null = Add-PASApplication @addParams
        Write-Log 'INFO' ("Application '{0}' created successfully." -f $AppID)

        Write-Log 'INFO' 'Verifying application was created...'
        $verifiedApp = $null
        $verifiedApp = Get-PASApplication -Search $AppID | Where-Object { $_.AppID -eq $AppID } | Select-Object -First 1

        if ($null -ne $verifiedApp) {
            Write-Output ''
            Write-Output 'Application Details:'
            Write-Output ('=' * 80)
            Write-Output ("  AppID: {0}" -f $verifiedApp.AppID)

            if ($verifiedApp.Description) {
                Write-Output ("  Description: {0}" -f $verifiedApp.Description)
            }

            if ($verifiedApp.Location) {
                Write-Output ("  Location: {0}" -f $verifiedApp.Location)
            }

            Write-Output ("  Disabled: {0}" -f $verifiedApp.Disabled)

            if ($null -ne $verifiedApp.AccessPermittedFrom -or $null -ne $verifiedApp.AccessPermittedTo) {
                Write-Output ("  Access Hours: {0} - {1}" -f $verifiedApp.AccessPermittedFrom, $verifiedApp.AccessPermittedTo)
            }

            if ($verifiedApp.ExpirationDate) {
                Write-Output ("  Expiration Date: {0}" -f $verifiedApp.ExpirationDate)
            }

            if ($verifiedApp.BusinessOwnerFName -or $verifiedApp.BusinessOwnerLName) {
                Write-Output ("  Business Owner: {0} {1}" -f $verifiedApp.BusinessOwnerFName, $verifiedApp.BusinessOwnerLName)
            }

            if ($verifiedApp.BusinessOwnerEmail) {
                Write-Output ("  Business Owner Email: {0}" -f $verifiedApp.BusinessOwnerEmail)
            }

            if ($verifiedApp.BusinessOwnerPhone) {
                Write-Output ("  Business Owner Phone: {0}" -f $verifiedApp.BusinessOwnerPhone)
            }

            Write-Output ('=' * 80)
        } else {
            Write-Log 'WARN' ("Application '{0}' was created but could not be re-read for display." -f $AppID)
        }
    }
} catch {
    $exitCode = 1
    Write-Output ''
    Write-Log 'ERROR' ("Error occurred: {0}" -f $_.Exception.Message)
} finally {
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

    $Credential = $null

    exit $exitCode
}
