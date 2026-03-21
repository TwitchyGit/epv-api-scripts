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

    [Parameter(Mandatory = $false, HelpMessage = 'Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off')]
    [Alias('session', 'sessionToken')]
    [string]$LogonToken
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

# -------------------------------------------------------------------
# Initial state
# -------------------------------------------------------------------
$exitCode = 0
$sessionToken = $null
$shouldLogoff = $true
$plainPassword = $null
$headers = @()

# Normalize URL once at the start
$PVWAUrl = $PVWAUrl.Trim().TrimEnd('/')

# -------------------------------------------------------------------
# Basic validation
# -------------------------------------------------------------------
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

# -------------------------------------------------------------------
# Optional certificate validation bypass
# -------------------------------------------------------------------
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

# Ensure TLS 1.2 is enabled without wiping other flags
if (([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12) -eq 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

# -------------------------------------------------------------------
# Authentication / session handling
# -------------------------------------------------------------------
if (-not [string]::IsNullOrWhiteSpace($LogonToken)) {
    # Reuse caller provided token
    $sessionToken = $LogonToken.Trim()
    $shouldLogoff = $false
    Write-Log 'INFO' 'Using provided session token. Script will not log off.'
} else {
    # Prompt if credential not supplied
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

    # Build password string for logon
    # RADIUS uses password,OTP format
    $passwordToSend = $plainPassword
    if ($AuthenticationType -eq 'radius') {
        $passwordToSend = '{0},{1}' -f $plainPassword, $OTP.Trim()
    }

    # Build logon body
    # Do not log this body because it contains sensitive data
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

# Headers used for subsequent API calls
$headers = @{
    Authorization = $sessionToken
    'Content-Type' = 'application/json'
}

# Encode AppID for URL safety
$appIdEncoded = ConvertTo-URL -Text $AppID

# Gen1 application endpoints
$getAppUrl = "{0}/WebServices/PIMServices.svc/Applications/{1}/" -f $PVWAUrl, $appIdEncoded
$deleteAppUrl = "{0}/WebServices/PIMServices.svc/Applications/{1}/" -f $PVWAUrl, $appIdEncoded

try {
    # -------------------------------------------------------------------
    # Retrieve application details before deletion
    # -------------------------------------------------------------------
    Write-Log 'INFO' ("Retrieving application details for '{0}'..." -f $AppID)
    $appDetails = Invoke-CyberArkRest -Method GET -Uri $getAppUrl -Headers $headers

    if (-not $appDetails.application) {
        throw "Application '$AppID' not found."
    }

    # Handle either wrapped array or direct object shape
    $app = $null
    if ($appDetails.application -is [array]) {
        $app = $appDetails.application[0]
    } else {
        $app = $appDetails.application
    }

    if ($null -eq $app) {
        throw "Application '$AppID' not found."
    }

    # -------------------------------------------------------------------
    # Display application selected for deletion
    # -------------------------------------------------------------------
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

    # -------------------------------------------------------------------
    # Confirm deletion
    # -------------------------------------------------------------------
    $confirmation = Read-Host ("Are you sure you want to delete application '{0}'? Type yes to continue" -f $AppID)
    if ($confirmation -ne 'yes') {
        Write-Log 'WARN' 'Deletion cancelled by user.'
        exit 1
    }

    # -------------------------------------------------------------------
    # Delete application
    # -------------------------------------------------------------------
    Write-Log 'INFO' ("Deleting application '{0}'..." -f $AppID)
    $null = Invoke-CyberArkRest -Method DELETE -Uri $deleteAppUrl -Headers $headers
    Write-Log 'INFO' ("Application '{0}' deleted successfully." -f $AppID)

    # -------------------------------------------------------------------
    # Verify deletion
    # -------------------------------------------------------------------
    Write-Log 'INFO' 'Verifying application was deleted...'

    try {
        $null = Invoke-CyberArkRest -Method GET -Uri $getAppUrl -Headers $headers
        Write-Log 'WARN' ("Application '{0}' still appears to exist." -f $AppID)
        $exitCode = 1
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
            Write-Log 'INFO' ("Confirmed: Application '{0}' no longer exists." -f $AppID)
        } else {
            Write-Log 'WARN' ("Could not verify deletion: {0}" -f $_.Exception.Message)
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
    # -------------------------------------------------------------------
    # Log off if we created the session
    # -------------------------------------------------------------------
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

    # Clear sensitive variable references
    $plainPassword = $null
    $Credential = $null

    exit $exitCode
}
