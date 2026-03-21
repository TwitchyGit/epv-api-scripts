<#
.SYNOPSIS
    Adds a new application to CyberArk.

.DESCRIPTION
    This script authenticates to CyberArk and creates a new application in the Vault.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g. https://pvwa.company.com)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER AppID
    The application name (required).

.PARAMETER Description
    Optional description of the application.

.PARAMETER Location
    Optional location of the application in the Vault hierarchy.

.PARAMETER AccessPermittedFrom
    Optional start hour that access is permitted (0-23).

.PARAMETER AccessPermittedTo
    Optional end hour that access is permitted (0-23).

.PARAMETER ExpirationDate
    Optional expiration date of the application (mm-dd-yyyy format).

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
    Disables SSL certificate validation. Use only for testing with self-signed certificates.

.EXAMPLE
    $cred = Get-Credential
    .\New-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com" `
        -Credential $cred `
        -AppID "MyNewApp" `
        -Description "My application for testing" `
        -Location "\Applications"

.EXAMPLE
    .\New-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com" `
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

    [Parameter(Mandatory = $false, HelpMessage = 'Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off')]
    [Alias('session', 'sessionToken')]
    [string]$LogonToken
)

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )

    # Simple logging
    Write-Output ("{0} {1}" -f $Level.ToUpper().PadRight(5), $Message)
}

function Convert-SecureStringToPlainText {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecureString
    )

    # Convert SecureString for API logon
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

    # Encode values for URLs
    if (-not [string]::IsNullOrWhiteSpace($Text)) {
        return [URI]::EscapeDataString($Text)
    }

    return $Text
}

function Invoke-CyberArkRest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $false)]
        [string]$Body
    )

    # Consistent REST wrapper
    if ([string]::IsNullOrWhiteSpace($Body)) {
        return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -ContentType 'application/json' -ErrorAction Stop
    } else {
        return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -Body $Body -ContentType 'application/json' -ErrorAction Stop
    }
}

# Initial state
$exitCode = 0
$sessionToken = $null
$shouldLogoff = $true
$plainPassword = $null
$headers = @{}

# Normalize URL once
$PVWAUrl = $PVWAUrl.Trim().TrimEnd('/')

# Basic validation
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
    $parsedDate = $null
    if (-not [datetime]::TryParseExact($ExpirationDate, 'MM-dd-yyyy', $null, [System.Globalization.DateTimeStyles]::None, [ref]$parsedDate)) {
        Write-Log 'ERROR' 'ExpirationDate must be in MM-dd-yyyy format.'
        exit 1
    }
}

# Optional certificate validation bypass
if ($DisableCertificateValidation) {
    Write-Log 'WARN' 'Certificate validation is disabled. Use only for testing.'

    if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint,
        X509Certificate certificate,
        WebRequest request,
        int certificateProblem) {
        return true;
    }
}
"@
    }

    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

# Ensure TLS 1.2 is enabled
if (([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12) -eq 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

# Authentication and session handling
if (-not [string]::IsNullOrWhiteSpace($LogonToken)) {
    $sessionToken = $LogonToken.Trim()
    $shouldLogoff = $false
    Write-Log 'INFO' 'Using provided session token. Script will not log off.'
} else {
    if (-not $Credential) {
        $Credential = Get-Credential -Message 'Enter CyberArk credentials'
    }

    if (-not $Credential) {
        Write-Log 'ERROR' 'Credentials are required to proceed.'
        exit 1
    }

    $userName = $Credential.UserName
    $plainPassword = Convert-SecureStringToPlainText -SecureString $Credential.Password

    if ([string]::IsNullOrWhiteSpace($plainPassword)) {
        Write-Log 'ERROR' 'Password could not be extracted from credential object.'
        exit 1
    }

    Write-Log 'INFO' ("Authenticating to CyberArk using {0}..." -f $AuthenticationType)

    $passwordToSend = $plainPassword
    if ($AuthenticationType -eq 'radius') {
        $passwordToSend = '{0},{1}' -f $plainPassword, $OTP.Trim()
    }

    # Do not log this body
    $authBody = @{
        username          = $userName
        password          = $passwordToSend
        concurrentSession = $true
    } | ConvertTo-Json

    $authUrl = "{0}/API/Auth/{1}/Logon" -f $PVWAUrl, $AuthenticationType

    try {
        $authResponse = Invoke-CyberArkRest -Method POST -Uri $authUrl -Body $authBody
        $sessionToken = [string]$authResponse
        Write-Log 'INFO' 'Authentication successful.'
    } catch {
        Write-Log 'ERROR' ("Authentication failed: {0}" -f $_.Exception.Message)
        if ($_.ErrorDetails.Message) {
            Write-Log 'ERROR' ("API Error Details: {0}" -f $_.ErrorDetails.Message)
        }
        exit 1
    }
}

# Headers for subsequent calls
$headers = @{
    Authorization = $sessionToken
    'Content-Type' = 'application/json'
}

# Encode AppID for URL safety
$appIdEncoded = ConvertTo-URL -Text $AppID

# Gen1 application endpoints
$checkUrl = "{0}/WebServices/PIMServices.svc/Applications/{1}/" -f $PVWAUrl, $appIdEncoded
$createAppUrl = "{0}/WebServices/PIMServices.svc/Applications/" -f $PVWAUrl

try {
    # Check whether application already exists
    Write-Log 'INFO' ("Checking if application '{0}' already exists..." -f $AppID)

    $appExists = $false

    try {
        $existingApp = Invoke-CyberArkRest -Method GET -Uri $checkUrl -Headers $headers
        if ($null -ne $existingApp) {
            $appExists = $true
        }
    } catch {
        $statusCode = $null

        try {
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
        } catch {
            $statusCode = $null
        }

        if ($statusCode -eq 404 -or $_.Exception.Message -match '404') {
            Write-Log 'INFO' 'Application does not exist. Proceeding with creation.'
        } else {
            throw
        }
    }

    if ($appExists) {
        Write-Log 'ERROR' ("Application '{0}' already exists. Use a different name or delete the existing application first." -f $AppID)
        $exitCode = 1
    }

    # Prepare application object
    if ($exitCode -eq 0) {
        $applicationObject = @{
            AppID    = $AppID
            Disabled = $Disabled
        }

        if (-not [string]::IsNullOrWhiteSpace($Description)) { $applicationObject['Description'] = $Description.Trim() }
        if (-not [string]::IsNullOrWhiteSpace($Location)) { $applicationObject['Location'] = $Location.Trim() }
        if ($PSBoundParameters.ContainsKey('AccessPermittedFrom')) { $applicationObject['AccessPermittedFrom'] = $AccessPermittedFrom }
        if ($PSBoundParameters.ContainsKey('AccessPermittedTo')) { $applicationObject['AccessPermittedTo'] = $AccessPermittedTo }
        if (-not [string]::IsNullOrWhiteSpace($ExpirationDate)) { $applicationObject['ExpirationDate'] = $ExpirationDate.Trim() }
        if (-not [string]::IsNullOrWhiteSpace($BusinessOwnerFName)) { $applicationObject['BusinessOwnerFName'] = $BusinessOwnerFName.Trim() }
        if (-not [string]::IsNullOrWhiteSpace($BusinessOwnerLName)) { $applicationObject['BusinessOwnerLName'] = $BusinessOwnerLName.Trim() }
        if (-not [string]::IsNullOrWhiteSpace($BusinessOwnerEmail)) { $applicationObject['BusinessOwnerEmail'] = $BusinessOwnerEmail.Trim() }
        if (-not [string]::IsNullOrWhiteSpace($BusinessOwnerPhone)) { $applicationObject['BusinessOwnerPhone'] = $BusinessOwnerPhone.Trim() }

        $requestBody = @{
            application = $applicationObject
        } | ConvertTo-Json -Depth 5

        # Create application
        Write-Log 'INFO' ("Creating application '{0}'..." -f $AppID)
        $null = Invoke-CyberArkRest -Method POST -Uri $createAppUrl -Headers $headers -Body $requestBody
        Write-Log 'INFO' ("Application '{0}' created successfully." -f $AppID)

        # Verify application creation
        Write-Log 'INFO' 'Verifying application was created...'
        $verifiedApp = Invoke-CyberArkRest -Method GET -Uri $checkUrl -Headers $headers

        $app = $null
        if ($verifiedApp.application) {
            if ($verifiedApp.application -is [array]) {
                $app = $verifiedApp.application[0]
            } else {
                $app = $verifiedApp.application
            }
        } else {
            $app = $verifiedApp
        }

        if ($null -ne $app) {
            Write-Output ''
            Write-Output 'Application Details:'
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
    }
} catch {
    $exitCode = 1
    Write-Output ''
    Write-Log 'ERROR' ("Error occurred: {0}" -f $_.Exception.Message)

    if ($_.ErrorDetails.Message) {
        Write-Log 'ERROR' ("API Error Details: {0}" -f $_.ErrorDetails.Message)
    }
} finally {
    # Log off if we created the session
    if ($shouldLogoff -and -not [string]::IsNullOrWhiteSpace($sessionToken)) {
        try {
            Write-Log 'INFO' 'Logging off...'
            $logoffUrl = "{0}/API/Auth/Logoff" -f $PVWAUrl
            $null = Invoke-CyberArkRest -Method POST -Uri $logoffUrl -Headers @{ Authorization = $sessionToken }
            Write-Log 'INFO' 'Session closed successfully.'
        } catch {
            Write-Log 'WARN' ("Could not close session properly: {0}" -f $_.Exception.Message)
        }
    } else {
        Write-Log 'INFO' 'Session token was provided. Not logging off.'
    }

    # Clear sensitive references
    $plainPassword = $null
    $Credential = $null

    exit $exitCode
}
