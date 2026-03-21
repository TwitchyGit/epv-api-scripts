<#
.SYNOPSIS
    Deletes an authentication method from a CyberArk Application.

.DESCRIPTION
    This script authenticates to CyberArk and deletes a specific authentication
    method from a specified application using the AuthID.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g. https://pvwa.company.com)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER AppID
    The Application ID from which the authentication will be deleted

.PARAMETER AuthID
    The unique ID of the authentication method to delete.
    Use Get-CyberArkAppAuthentication.ps1 to find the AuthID.

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation. Use only for testing with self-signed certificates.

.EXAMPLE
    $cred = Get-Credential
    .\Remove-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
        -Credential $cred `
        -AppID "MyApp" `
        -AuthID 5

.EXAMPLE
    .\Remove-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
        -AppID "MyApp" `
        -AuthID 5
    # Credentials will be prompted if not provided

.EXAMPLE
    # List authentication methods to find AuthID, then delete
    .\Get-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp"
    .\Remove-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp" -AuthID 5
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppID,

    [Parameter(Mandatory = $true)]
    [int]$AuthID,

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
$headers = @{}

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

if ($AuthID -lt 1) {
    Write-Log 'ERROR' 'AuthID must be greater than 0.'
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
$getAuthUrl = "{0}/WebServices/PIMServices.svc/Applications/{1}/Authentications/" -f $PVWAUrl, $appIdEncoded
$deleteAuthUrl = "{0}/WebServices/PIMServices.svc/Applications/{1}/Authentications/{2}/" -f $PVWAUrl, $appIdEncoded, $AuthID

try {
    # -------------------------------------------------------------------
    # Retrieve authentication methods
    # -------------------------------------------------------------------
    Write-Log 'INFO' ("Retrieving authentication methods for application '{0}'..." -f $AppID)
    $authMethods = Invoke-CyberArkRest -Method GET -Uri $getAuthUrl -Headers $headers

    if (-not $authMethods.authentication) {
        throw "No authentication methods were found for application '$AppID'."
    }

    # Find requested authentication by AuthID
    $authToDelete = @($authMethods.authentication | Where-Object { $_.authID -eq $AuthID })

    if ($authToDelete.Count -eq 0) {
        throw "Authentication with AuthID $AuthID not found for application '$AppID'."
    }

    if ($authToDelete.Count -gt 1) {
        throw "Multiple authentication records were returned for AuthID $AuthID on application '$AppID'."
    }

    $authToDelete = $authToDelete[0]

    # -------------------------------------------------------------------
    # Display authentication selected for deletion
    # -------------------------------------------------------------------
    Write-Output ''
    Write-Output 'Authentication to be deleted:'
    Write-Output ("  - Auth ID: {0} | Type: {1}" -f $authToDelete.authID, $authToDelete.AuthType)

    if ($authToDelete.AuthValue) {
        Write-Output ("    AuthValue: {0}" -f $authToDelete.AuthValue)
    }

    if ($authToDelete.Subject) {
        Write-Output ("    Subject: {0}" -f (@($authToDelete.Subject) -join ', '))
    }

    if ($authToDelete.Issuer) {
        Write-Output ("    Issuer: {0}" -f (@($authToDelete.Issuer) -join ', '))
    }

    if ($authToDelete.SubjectAlternativeName) {
        Write-Output ("    SubjectAlternativeName: {0}" -f (@($authToDelete.SubjectAlternativeName) -join ', '))
    }

    if ($authToDelete.Comment) {
        Write-Output ("    Comment: {0}" -f $authToDelete.Comment)
    }

    if ($null -ne $authToDelete.IsFolder) {
        Write-Output ("    IsFolder: {0}" -f $authToDelete.IsFolder)
    }

    if ($null -ne $authToDelete.AllowInternalScripts) {
        Write-Output ("    AllowInternalScripts: {0}" -f $authToDelete.AllowInternalScripts)
    }

    # -------------------------------------------------------------------
    # Confirm deletion
    # -------------------------------------------------------------------
    $confirmation = Read-Host "Are you sure you want to delete this authentication? Type yes to continue"
    if ($confirmation -ne 'yes') {
        Write-Log 'WARN' 'Deletion cancelled by user.'
        exit 1
    }

    # -------------------------------------------------------------------
    # Delete authentication method
    # -------------------------------------------------------------------
    Write-Log 'INFO' ("Deleting authentication AuthID {0} from application '{1}'..." -f $AuthID, $AppID)
    $null = Invoke-CyberArkRest -Method DELETE -Uri $deleteAuthUrl -Headers $headers
    Write-Log 'INFO' ("Authentication AuthID {0} was deleted from application '{1}'." -f $AuthID, $AppID)

    # -------------------------------------------------------------------
    # Verify deletion
    # -------------------------------------------------------------------
    Write-Log 'INFO' 'Verifying authentication was deleted...'
    $authMethodsAfterDelete = Invoke-CyberArkRest -Method GET -Uri $getAuthUrl -Headers $headers
    $stillExists = @($authMethodsAfterDelete.authentication | Where-Object { $_.authID -eq $AuthID })

    if ($stillExists.Count -eq 0) {
        Write-Log 'INFO' ("Confirmed: Authentication AuthID {0} no longer exists." -f $AuthID)
    } else {
        Write-Log 'WARN' ("Authentication AuthID {0} still appears to exist." -f $AuthID)
        $exitCode = 1
    }

    # -------------------------------------------------------------------
    # Display remaining authentication methods
    # -------------------------------------------------------------------
    if ($authMethodsAfterDelete.authentication) {
        Write-Output ''
        Write-Output ("Remaining authentication method(s) for application '{0}': {1}" -f $AppID, $authMethodsAfterDelete.authentication.Count)
        Write-Output ('=' * 80)

        foreach ($auth in $authMethodsAfterDelete.authentication) {
            Write-Output ("  - Auth ID: {0} | Type: {1}" -f $auth.authID, $auth.AuthType)

            if ($auth.AuthValue) {
                Write-Output ("    AuthValue: {0}" -f $auth.AuthValue)
            }
        }

        Write-Output ('=' * 80)
    } else {
        Write-Output ''
        Write-Log 'INFO' ("No authentication methods remain for application '{0}'." -f $AppID)
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
