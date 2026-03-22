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

    [Parameter(Mandatory = $false, HelpMessage = 'Pass an existing psPAS session object. If passed the session is NOT logged off')]
    [Alias('session', 'sessionToken')]
    [object]$LogonToken
)

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )

    # Simple operator-friendly logging
    Write-Output ("{0} {1}" -f $Level.ToUpper().PadRight(5), $Message)
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

# Initial state
$exitCode = 0
$shouldLogoff = $true
$authMethodsToAdd = @()
$existingAuthMethods = @()
$addedAuths = @()
$skippedAuths = @()
$failedAuths = @()

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

# Build requested authentication methods

# Path authentication
if ($Path) {
    foreach ($p in $Path) {
        if (-not [string]::IsNullOrWhiteSpace($p)) {
            $authMethodsToAdd += @{
                Type   = 'Path'
                Object = @{
                    path                 = $p.Trim()
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
                hash = $h.Trim()
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
                    osUser = $user.Trim()
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
                    machineAddress = $addr.Trim()
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
                certificateserialnumber = $serial.Trim()
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
    $authObj = @{}

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

# Authentication / session handling
if ($null -ne $LogonToken) {
    # Reuse caller-provided psPAS session
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

# Validate application exists
Write-Log 'INFO' ("Validating application '{0}' exists..." -f $AppID)

try {
    $null = Get-PASApplication -AppID $AppID -ExactMatch
    Write-Log 'INFO' ("Application '{0}' verified." -f $AppID)
} catch {
    Write-Log 'ERROR' ("Could not validate application '{0}': {1}" -f $AppID, $_.Exception.Message)
    $exitCode = 1
}

# If no auth methods were requested, treat as verify-only mode
if ($exitCode -eq 0 -and $authMethodsToAdd.Count -eq 0) {
    Write-Log 'INFO' 'No authentication methods were specified. Verification only completed successfully.'
}

# Read existing authentication methods
if ($exitCode -eq 0 -and $authMethodsToAdd.Count -gt 0) {
    Write-Log 'INFO' ("Retrieving existing authentication methods for application '{0}'..." -f $AppID)

    try {
        $result = Get-PASApplicationAuthenticationMethod -AppID $AppID
        if ($null -ne $result) {
            $existingAuthMethods = @($result)
        } else {
            $existingAuthMethods = @()
        }
    } catch {
        Write-Log 'ERROR' ("Could not retrieve existing authentication methods: {0}" -f $_.Exception.Message)
        $exitCode = 1
    }
}

# Add authentication methods
if ($exitCode -eq 0 -and $authMethodsToAdd.Count -gt 0) {
    foreach ($authMethod in $authMethodsToAdd) {
        $authType = $authMethod.Type
        $authObj = $authMethod.Object
        $isDuplicate = $false

        # Check for duplicates before add
        foreach ($existing in $existingAuthMethods) {
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
                if ((Normalize-Scalar $existing.AuthType) -eq 'path' -and $authType -eq 'Path' -and
                    (Normalize-Scalar $existing.AuthValue) -eq (Normalize-Scalar $authObj.path)) {
                    $isDuplicate = $true
                    break
                }

                if ((Normalize-Scalar $existing.AuthType) -eq 'hash' -and $authType -eq 'Hash' -and
                    (Normalize-Scalar $existing.AuthValue) -eq (Normalize-Scalar $authObj.hash)) {
                    $isDuplicate = $true
                    break
                }

                if ((Normalize-Scalar $existing.AuthType) -eq 'osuser' -and $authType -eq 'OSUser' -and
                    (Normalize-Scalar $existing.AuthValue) -eq (Normalize-Scalar $authObj.osUser)) {
                    $isDuplicate = $true
                    break
                }

                if ((Normalize-Scalar $existing.AuthType) -eq 'machineaddress' -and $authType -eq 'MachineAddress' -and
                    (Normalize-Scalar $existing.AuthValue) -eq (Normalize-Scalar $authObj.machineAddress)) {
                    $isDuplicate = $true
                    break
                }

                if ((Normalize-Scalar $existing.AuthType) -eq 'certificateserialnumber' -and $authType -eq 'CertificateSerialNumber' -and
                    (Normalize-Scalar $existing.AuthValue) -eq (Normalize-Scalar $authObj.certificateserialnumber)) {
                    $isDuplicate = $true
                    break
                }
            }
        }

        # Friendly value for output
        $displayValue = 'Certificate Attributes'
        if ($authType -eq 'Path') { $displayValue = $authObj.path }
        if ($authType -eq 'Hash') { $displayValue = $authObj.hash }
        if ($authType -eq 'OSUser') { $displayValue = $authObj.osUser }
        if ($authType -eq 'MachineAddress') { $displayValue = $authObj.machineAddress }
        if ($authType -eq 'CertificateSerialNumber') { $displayValue = $authObj.certificateserialnumber }

        if ($isDuplicate) {
            $skippedAuths += ("{0}: {1} (duplicate)" -f $authType, $displayValue)
            Write-Log 'INFO' ("Skipping {0} authentication. Already exists: {1}" -f $authType, $displayValue)
            continue
        }

        # Add each authentication method using the relevant psPAS parameter set
        try {
            Write-Log 'INFO' ("Adding {0} authentication: {1}" -f $authType, $displayValue)

            if ($authType -eq 'Path') {
                $null = Add-PASApplicationAuthenticationMethod -AppID $AppID -path $authObj.path -IsFolder $authObj.IsFolder -AllowInternalScripts $authObj.AllowInternalScripts
            }

            if ($authType -eq 'Hash') {
                if ($authObj.ContainsKey('Comment')) {
                    $null = Add-PASApplicationAuthenticationMethod -AppID $AppID -hash $authObj.hash -Comment $authObj.Comment
                } else {
                    $null = Add-PASApplicationAuthenticationMethod -AppID $AppID -hash $authObj.hash
                }
            }

            if ($authType -eq 'OSUser') {
                $null = Add-PASApplicationAuthenticationMethod -AppID $AppID -osUser $authObj.osUser
            }

            if ($authType -eq 'MachineAddress') {
                $null = Add-PASApplicationAuthenticationMethod -AppID $AppID -machineAddress $authObj.machineAddress
            }

            if ($authType -eq 'CertificateSerialNumber') {
                if ($authObj.ContainsKey('Comment')) {
                    $null = Add-PASApplicationAuthenticationMethod -AppID $AppID -certificateserialnumber $authObj.certificateserialnumber -Comment $authObj.Comment
                } else {
                    $null = Add-PASApplicationAuthenticationMethod -AppID $AppID -certificateserialnumber $authObj.certificateserialnumber
                }
            }

            if ($authType -eq 'CertificateAttr') {
                $addAttrParams = @{
                    AppID = $AppID
                }

                if ($authObj.ContainsKey('Subject')) { $addAttrParams['Subject'] = $authObj.Subject }
                if ($authObj.ContainsKey('Issuer')) { $addAttrParams['Issuer'] = $authObj.Issuer }
                if ($authObj.ContainsKey('SubjectAlternativeName')) { $addAttrParams['SubjectAlternativeName'] = $authObj.SubjectAlternativeName }

                $null = Add-PASApplicationAuthenticationMethod @addAttrParams
            }

            $addedAuths += ("{0}: {1}" -f $authType, $displayValue)
            Write-Log 'INFO' ("Successfully added {0} authentication: {1}" -f $authType, $displayValue)
        } catch {
            $failedAuths += ("{0}: {1} - {2}" -f $authType, $displayValue, $_.Exception.Message)
            Write-Log 'ERROR' ("Failed to add {0} authentication: {1}" -f $authType, $_.Exception.Message)
        }
    }
}

# Summary
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

# Display updated authentication list
if ($exitCode -eq 0 -and $addedAuths.Count -gt 0) {
    Write-Log 'INFO' 'Retrieving updated authentication methods...'

    try {
        $authMethods = Get-PASApplicationAuthenticationMethod -AppID $AppID

        if ($authMethods) {
            $authMethods = @($authMethods)

            Write-Output ''
            Write-Log 'INFO' ("Application '{0}' now has {1} authentication method(s):" -f $AppID, $authMethods.Count)
            Write-Output ('=' * 80)

            foreach ($auth in $authMethods) {
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
    }
}

# Logoff if we created the session
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

# Clear sensitive variable reference
$Credential = $null

exit $exitCode
