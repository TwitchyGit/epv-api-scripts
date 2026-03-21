<#
.SYNOPSIS
    Adds one or more authentication methods to a CyberArk Application.

.DESCRIPTION
    This script authenticates to CyberArk and adds authentication methods to a specified application.
    You can add multiple authentication types in a single call by specifying multiple parameters.

    If no authentication methods are specified, the script will only verify that the application exists.

    Supported authentication types:
    - Path: File or folder path (use -Path parameter)
    - Hash: File hash (use -Hash parameter)
    - OS User: Windows user account (use -OSUser parameter)
    - Machine Address: IP address or subnet (use -MachineAddress parameter)
    - Certificate Serial Number: Certificate serial number (use -CertificateSerialNumber parameter)
    - Certificate Attributes: Certificate subject/issuer (use -CertificateIssuer, -CertificateSubject, -CertificateSubjectAlternativeName)

.PARAMETER AppID
    The Application ID to which authentication methods will be added

.PARAMETER Path
    Path to executable or folder for Path authentication. Can provide multiple paths as an array.

.PARAMETER PathIsFolder
    For Path authentication - whether the path is a folder. Default: $false

.PARAMETER PathAllowInternalScripts
    For Path authentication - whether to allow internal scripts. Default: $false

.PARAMETER Hash
    File hash value for Hash authentication. Can provide multiple hashes as an array.

.PARAMETER HashComment
    Optional comment for Hash authentication

.PARAMETER OSUser
    Windows user account (e.g. "DOMAIN\User") for OS User authentication. Can provide multiple as an array.

.PARAMETER MachineAddress
    IP address or subnet (e.g. "192.168.1.100" or "192.168.1.0/24") for Machine Address authentication. Can provide multiple as an array.

.PARAMETER CertificateSerialNumber
    Certificate serial number for Certificate Serial Number authentication. Can provide multiple as an array.

.PARAMETER CertificateSerialNumberComment
    Optional comment for Certificate Serial Number authentication

.PARAMETER CertificateIssuer
    Array of certificate issuer attributes (e.g. @("CN=Company CA","OU=IT")) for Certificate Attributes authentication

.PARAMETER CertificateSubject
    Array of certificate subject attributes (e.g. @("CN=app.company.com","OU=IT")) for Certificate Attributes authentication

.PARAMETER CertificateSubjectAlternativeName
    Array of certificate SAN attributes (e.g. @("DNS Name=www.example.com")) for Certificate Attributes authentication

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g. https://pvwa.company.com)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation. Use only for testing with self-signed certificates.

.EXAMPLE
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" -PVWAUrl "https://pvwa.company.com" -Path "C:\Program Files\MyApp\app.exe"

.EXAMPLE
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" -PVWAUrl "https://pvwa.company.com" `
        -Path "C:\Program Files\MyApp\app.exe" `
        -OSUser "DOMAIN\ServiceAccount" `
        -MachineAddress "192.168.1.0/24"

.EXAMPLE
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" -PVWAUrl "https://pvwa.company.com" `
        -Path @("C:\App\app1.exe", "C:\App\app2.exe")

.EXAMPLE
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" -PVWAUrl "https://pvwa.company.com" `
        -CertificateSubject @("CN=app.company.com","OU=IT") `
        -CertificateIssuer @("CN=Company Root CA")

.EXAMPLE
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" -PVWAUrl "https://pvwa.company.com" `
        -Hash "A1B2C3D4E5F6" `
        -HashComment "Production server hash"

.EXAMPLE
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" -PVWAUrl "https://pvwa.company.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppID,

    [Parameter(Mandatory = $false)]
    [string[]]$Path,

    [Parameter(Mandatory = $false)]
    [bool]$PathIsFolder = $false,

    [Parameter(Mandatory = $false)]
    [bool]$PathAllowInternalScripts = $false,

    [Parameter(Mandatory = $false)]
    [string[]]$Hash,

    [Parameter(Mandatory = $false)]
    [string]$HashComment,

    [Parameter(Mandatory = $false)]
    [string[]]$OSUser,

    [Parameter(Mandatory = $false)]
    [string[]]$MachineAddress,

    [Parameter(Mandatory = $false)]
    [string[]]$CertificateSerialNumber,

    [Parameter(Mandatory = $false)]
    [string]$CertificateSerialNumberComment,

    [Parameter(Mandatory = $false)]
    [string[]]$CertificateIssuer,

    [Parameter(Mandatory = $false)]
    [string[]]$CertificateSubject,

    [Parameter(Mandatory = $false)]
    [string[]]$CertificateSubjectAlternativeName,

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

    # Simple operator-friendly logging
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

function Normalize-Scalar {
    param(
        [AllowNull()]
        [string]$Value
    )

    # Normalize single values for duplicate comparison
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    return $Value.Trim().ToLowerInvariant()
}

function Normalize-StringArray {
    param(
        [AllowNull()]
        [string[]]$Values
    )

    # Normalize, trim and sort arrays for duplicate comparison
    $output = @()

    if ($Values) {
        foreach ($item in $Values) {
            if (-not [string]::IsNullOrWhiteSpace($item)) {
                $output += $item.Trim()
            }
        }
    }

    return @($output | Sort-Object)
}

function Compare-NormalizedStringArrays {
    param(
        [AllowNull()]
        [string[]]$Left,

        [AllowNull()]
        [string[]]$Right
    )

    # Compare arrays after trim/sort/case normalization
    $leftNorm = @(Normalize-StringArray -Values $Left)
    $rightNorm = @(Normalize-StringArray -Values $Right)

    if ($leftNorm.Count -ne $rightNorm.Count) {
        return $false
    }

    for ($i = 0; $i -lt $leftNorm.Count; $i++) {
        if ($leftNorm[$i].ToLowerInvariant() -ne $rightNorm[$i].ToLowerInvariant()) {
            return $false
        }
    }

    return $true
}

function Invoke-CyberArkRest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Get', 'Post')]
        [string]$Method,

        [Parameter(Mandatory = $false)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $false)]
        [string]$Body
    )

    # Small wrapper so all REST calls are consistent
    if ([string]::IsNullOrWhiteSpace($Body)) {
        return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -ErrorAction Stop
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
$authMethodsToAdd = @()

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

    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

# Ensure TLS 1.2 is enabled without wiping other flags
if (([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12) -eq 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

# -------------------------------------------------------------------
# Build requested authentication methods
# -------------------------------------------------------------------

# Path authentication
if ($Path) {
    foreach ($p in $Path) {
        if (-not [string]::IsNullOrWhiteSpace($p)) {
            $authMethodsToAdd += @{
                Type   = 'Path'
                Object = @{
                    AuthType             = 'path'
                    AuthValue            = $p.Trim()
                    IsFolder             = $PathIsFolder
                    AllowInternalScripts = $PathAllowInternalScripts
                }
            }
        }
    }
}

# Hash authentication
if ($Hash) {
    foreach ($h in $Hash) {
        if (-not [string]::IsNullOrWhiteSpace($h)) {
            $authObj = @{
                AuthType  = 'hash'
                AuthValue = $h.Trim()
            }

            if (-not [string]::IsNullOrWhiteSpace($HashComment)) {
                $authObj['Comment'] = $HashComment.Trim()
            }

            $authMethodsToAdd += @{
                Type   = 'Hash'
                Object = $authObj
            }
        }
    }
}

# OS User authentication
if ($OSUser) {
    foreach ($user in $OSUser) {
        if (-not [string]::IsNullOrWhiteSpace($user)) {
            $authMethodsToAdd += @{
                Type   = 'OSUser'
                Object = @{
                    AuthType  = 'osUser'
                    AuthValue = $user.Trim()
                }
            }
        }
    }
}

# Machine Address authentication
if ($MachineAddress) {
    foreach ($addr in $MachineAddress) {
        if (-not [string]::IsNullOrWhiteSpace($addr)) {
            $authMethodsToAdd += @{
                Type   = 'MachineAddress'
                Object = @{
                    AuthType  = 'machineAddress'
                    AuthValue = $addr.Trim()
                }
            }
        }
    }
}

# Certificate Serial Number authentication
if ($CertificateSerialNumber) {
    foreach ($serial in $CertificateSerialNumber) {
        if (-not [string]::IsNullOrWhiteSpace($serial)) {
            $authObj = @{
                AuthType  = 'certificateserialnumber'
                AuthValue = $serial.Trim()
            }

            if (-not [string]::IsNullOrWhiteSpace($CertificateSerialNumberComment)) {
                $authObj['Comment'] = $CertificateSerialNumberComment.Trim()
            }

            $authMethodsToAdd += @{
                Type   = 'CertificateSerialNumber'
                Object = $authObj
            }
        }
    }
}

# Certificate Attributes authentication
if ($CertificateIssuer -or $CertificateSubject -or $CertificateSubjectAlternativeName) {
    $authObj = @{
        AuthType = 'certificateattr'
    }

    # Normalize arrays before sending and duplicate checks
    $issuerValues = @(Normalize-StringArray -Values $CertificateIssuer)
    $subjectValues = @(Normalize-StringArray -Values $CertificateSubject)
    $sanValues = @(Normalize-StringArray -Values $CertificateSubjectAlternativeName)

    if ($issuerValues.Count -gt 0) {
        $authObj['Issuer'] = $issuerValues
    }

    if ($subjectValues.Count -gt 0) {
        $authObj['Subject'] = $subjectValues
    }

    if ($sanValues.Count -gt 0) {
        $authObj['SubjectAlternativeName'] = $sanValues
    }

    $authMethodsToAdd += @{
        Type   = 'CertificateAttr'
        Object = $authObj
    }
}

# -------------------------------------------------------------------
# Authentication / session handling
# -------------------------------------------------------------------
if (-not [string]::IsNullOrWhiteSpace($LogonToken)) {
    # Reuse caller-provided token
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
        $authResponse = Invoke-CyberArkRest -Uri $authUrl -Method Post -Body $authBody
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
$appIdEncoded = [uri]::EscapeDataString($AppID)

# Gen1 application endpoints
$appUrl = "{0}/WebServices/PIMServices.svc/Applications/{1}/" -f $PVWAUrl, $appIdEncoded
$getAuthUrl = "{0}/WebServices/PIMServices.svc/Applications/{1}/Authentications/" -f $PVWAUrl, $appIdEncoded

# -------------------------------------------------------------------
# Validate application exists
# -------------------------------------------------------------------
try {
    Write-Log 'INFO' ("Validating application '{0}' exists..." -f $AppID)
    $null = Invoke-CyberArkRest -Uri $appUrl -Method Get -Headers $headers
    Write-Log 'INFO' ("Application '{0}' verified." -f $AppID)
} catch {
    Write-Log 'ERROR' ("Could not validate application '{0}': {1}" -f $AppID, $_.Exception.Message)
    if ($_.ErrorDetails.Message) {
        Write-Log 'ERROR' ("API Error Details: {0}" -f $_.ErrorDetails.Message)
    }
    $exitCode = 1
}

# If no auth methods were requested, treat as verify-only mode
if ($exitCode -eq 0 -and $authMethodsToAdd.Count -eq 0) {
    Write-Log 'INFO' 'No authentication methods were specified. Verification only completed successfully.'
}

# -------------------------------------------------------------------
# Read existing authentication methods
# -------------------------------------------------------------------
$existingAuthMethods = @{ authentication = @() }

if ($exitCode -eq 0 -and $authMethodsToAdd.Count -gt 0) {
    try {
        Write-Log 'INFO' ("Retrieving existing authentication methods for application '{0}'..." -f $AppID)
        $existingAuthMethods = Invoke-CyberArkRest -Uri $getAuthUrl -Method Get -Headers $headers

        # Some responses may not return an authentication property
        if (-not $existingAuthMethods.authentication) {
            $existingAuthMethods = @{ authentication = @() }
        }
    } catch {
        Write-Log 'ERROR' ("Could not retrieve existing authentication methods: {0}" -f $_.Exception.Message)
        if ($_.ErrorDetails.Message) {
            Write-Log 'ERROR' ("API Error Details: {0}" -f $_.ErrorDetails.Message)
        }
        $exitCode = 1
    }
}

# -------------------------------------------------------------------
# Add authentication methods
# -------------------------------------------------------------------
$addedAuths = @()
$skippedAuths = @()
$failedAuths = @()

if ($exitCode -eq 0 -and $authMethodsToAdd.Count -gt 0) {
    foreach ($authMethod in $authMethodsToAdd) {
        $authType = $authMethod.Type
        $authObj = $authMethod.Object
        $isDuplicate = $false

        # Check for duplicates before add
        foreach ($existing in $existingAuthMethods.authentication) {
            if ($authType -eq 'CertificateAttr' -and (Normalize-Scalar $existing.AuthType) -eq 'certificateattr') {
                # Certificate attributes use array comparisons
                $existingSubject = @()
                $existingIssuer = @()
                $existingSAN = @()

                if ($existing.Subject) { $existingSubject = @($existing.Subject) }
                if ($existing.Issuer) { $existingIssuer = @($existing.Issuer) }
                if ($existing.SubjectAlternativeName) { $existingSAN = @($existing.SubjectAlternativeName) }

                $subjectMatches = Compare-NormalizedStringArrays -Left $authObj.Subject -Right $existingSubject
                $issuerMatches = Compare-NormalizedStringArrays -Left $authObj.Issuer -Right $existingIssuer
                $sanMatches = Compare-NormalizedStringArrays -Left $authObj.SubjectAlternativeName -Right $existingSAN

                if ($subjectMatches -and $issuerMatches -and $sanMatches) {
                    $isDuplicate = $true
                    break
                }
            } else {
                # All other types compare AuthType + AuthValue
                if ((Normalize-Scalar $existing.AuthType) -eq (Normalize-Scalar $authObj.AuthType) -and
                    (Normalize-Scalar $existing.AuthValue) -eq (Normalize-Scalar $authObj.AuthValue)) {
                    $isDuplicate = $true
                    break
                }
            }
        }

        # Friendly value for output
        $displayValue = 'Certificate Attributes'
        if ($authObj.ContainsKey('AuthValue') -and -not [string]::IsNullOrWhiteSpace($authObj.AuthValue)) {
            $displayValue = $authObj.AuthValue
        }

        if ($isDuplicate) {
            $skippedAuths += ("{0}: {1} (duplicate)" -f $authType, $displayValue)
            Write-Log 'INFO' ("Skipping {0} authentication. Already exists: {1}" -f $authType, $displayValue)
            continue
        }

        # Build add body
        $requestBody = @{
            authentication = $authObj
        } | ConvertTo-Json -Depth 6

        try {
            Write-Log 'INFO' ("Adding {0} authentication: {1}" -f $authType, $displayValue)
            $null = Invoke-CyberArkRest -Uri $getAuthUrl -Method Post -Headers $headers -Body $requestBody
            $addedAuths += ("{0}: {1}" -f $authType, $displayValue)
            Write-Log 'INFO' ("Successfully added {0} authentication: {1}" -f $authType, $displayValue)
        } catch {
            $failedAuths += ("{0}: {1} - {2}" -f $authType, $displayValue, $_.Exception.Message)
            Write-Log 'ERROR' ("Failed to add {0} authentication: {1}" -f $authType, $_.Exception.Message)
            if ($_.ErrorDetails.Message) {
                Write-Log 'ERROR' ("API Error Details: {0}" -f $_.ErrorDetails.Message)
            }
        }
    }
}

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
Write-Output ''
Write-Output ('=' * 80)
Write-Output 'SUMMARY'
Write-Output ('=' * 80)

if ($addedAuths.Count -gt 0) {
    Write-Output ''
    Write-Log 'INFO' ("Added {0} authentication method(s):" -f $addedAuths.Count)
    foreach ($auth in $addedAuths) {
        Write-Output ("  - {0}" -f $auth)
    }
}

if ($skippedAuths.Count -gt 0) {
    Write-Output ''
    Write-Log 'INFO' ("Skipped {0} authentication method(s):" -f $skippedAuths.Count)
    foreach ($auth in $skippedAuths) {
        Write-Output ("  - {0}" -f $auth)
    }
}

if ($failedAuths.Count -gt 0) {
    Write-Output ''
    Write-Log 'ERROR' ("Failed {0} authentication method(s):" -f $failedAuths.Count)
    foreach ($auth in $failedAuths) {
        Write-Output ("  - {0}" -f $auth)
    }
    $exitCode = 1
}

# -------------------------------------------------------------------
# Display updated authentication list
# -------------------------------------------------------------------
if ($exitCode -eq 0 -and $addedAuths.Count -gt 0) {
    try {
        Write-Log 'INFO' 'Retrieving updated authentication methods...'
        $authMethods = Invoke-CyberArkRest -Uri $getAuthUrl -Method Get -Headers $headers

        if ($authMethods.authentication) {
            Write-Output ''
            Write-Log 'INFO' ("Application '{0}' now has {1} authentication method(s):" -f $AppID, $authMethods.authentication.Count)
            Write-Output ('=' * 80)

            foreach ($auth in $authMethods.authentication) {
                Write-Output ("  - Auth ID: {0} | Type: {1}" -f $auth.authID, $auth.AuthType)

                if ($auth.AuthValue) {
                    Write-Output ("    Value: {0}" -f $auth.AuthValue)
                }
                if ($auth.Subject) {
                    Write-Output ("    Subject: {0}" -f (@($auth.Subject) -join '; '))
                }
                if ($auth.Issuer) {
                    Write-Output ("    Issuer: {0}" -f (@($auth.Issuer) -join '; '))
                }
                if ($auth.SubjectAlternativeName) {
                    Write-Output ("    SubjectAlternativeName: {0}" -f (@($auth.SubjectAlternativeName) -join '; '))
                }
                if ($auth.Comment) {
                    Write-Output ("    Comment: {0}" -f $auth.Comment)
                }
                if ($null -ne $auth.IsFolder) {
                    Write-Output ("    IsFolder: {0}" -f $auth.IsFolder)
                }
                if ($null -ne $auth.AllowInternalScripts) {
                    Write-Output ("    AllowInternalScripts: {0}" -f $auth.AllowInternalScripts)
                }
            }

            Write-Output ('=' * 80)
        }
    } catch {
        Write-Log 'WARN' ("Could not retrieve updated authentication methods: {0}" -f $_.Exception.Message)
        if ($_.ErrorDetails.Message) {
            Write-Log 'WARN' ("API Error Details: {0}" -f $_.ErrorDetails.Message)
        }
    }
}

# -------------------------------------------------------------------
# Logoff if we created the session
# -------------------------------------------------------------------
if ($shouldLogoff -and -not [string]::IsNullOrWhiteSpace($sessionToken)) {
    try {
        Write-Log 'INFO' 'Logging off...'
        $logoffUrl = "{0}/API/Auth/Logoff" -f $PVWAUrl
        $null = Invoke-CyberArkRest -Uri $logoffUrl -Method Post -Headers @{ Authorization = $sessionToken }
        Write-Log 'INFO' 'Session closed successfully.'
    } catch {
        Write-Log 'WARN' ("Could not close session properly: {0}" -f $_.Exception.Message)
    }
} else {
    Write-Log 'INFO' 'Session token was provided. Not logging off.'
}

# Clear sensitive variable reference
$plainPassword = $null

exit $exitCode
