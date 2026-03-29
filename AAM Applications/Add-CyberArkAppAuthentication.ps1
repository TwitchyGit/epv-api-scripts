<#
.SYNOPSIS
    Adds or replaces authentication methods on a CyberArk Application.

.DESCRIPTION
    This script authenticates to CyberArk and adds or replaces authentication methods
    on a specified application.

    By default, supplied values are ADDED to any existing entries of the same type.
    Duplicates are detected and skipped automatically.

    To replace ALL existing entries of a given type with the newly supplied values,
    pass the corresponding -Replace<Type> switch. The script will delete every existing
    entry of that type and then add the new values fresh.

    If no authentication methods are specified the script runs in verify-only mode and
    confirms that the application exists.

    Supported authentication types:
      Path                  -Path               (optionally -ReplacePath)
      Hash                  -Hash               (optionally -ReplaceHash)
      OS User               -OSUser             (optionally -ReplaceOSUser)
      Machine Address       -MachineAddress     (optionally -ReplaceMachineAddress)
      Certificate Serial    -CertificateSerialNumber  (optionally -ReplaceCertificateSerialNumber)
      Certificate Attributes  -CertificateIssuer / -CertificateSubject /
                              -CertificateSubjectAlternativeName
                                                (optionally -ReplaceCertificateAttr)

.PARAMETER AppID
    The Application ID to which authentication methods will be added or replaced.

.PARAMETER Path
    Path to executable or folder for Path authentication. Accepts multiple values.

.PARAMETER ReplacePath
    When set, ALL existing Path authentication entries are deleted before the new values
    in -Path are added.

.PARAMETER PathIsFolder
    For Path authentication — whether the path is a folder. Default: $false.

.PARAMETER PathAllowInternalScripts
    For Path authentication — whether to allow internal scripts. Default: $false.

.PARAMETER Hash
    File hash value(s) for Hash authentication. Accepts multiple values.

.PARAMETER ReplaceHash
    When set, ALL existing Hash authentication entries are deleted before the new values
    in -Hash are added.

.PARAMETER HashComment
    Optional comment applied to every Hash entry being added.

.PARAMETER OSUser
    Windows user account(s) (e.g. "DOMAIN\User") for OS User authentication.
    Accepts multiple values.

.PARAMETER ReplaceOSUser
    When set, ALL existing OSUser authentication entries are deleted before the new
    values in -OSUser are added.

.PARAMETER MachineAddress
    IP address or subnet(s) (e.g. "192.168.1.100" or "192.168.1.0/24") for Machine
    Address authentication. Accepts multiple values.

.PARAMETER ReplaceMachineAddress
    When set, ALL existing MachineAddress authentication entries are deleted before the
    new values in -MachineAddress are added.

.PARAMETER CertificateSerialNumber
    Certificate serial number(s) for Certificate Serial Number authentication.
    Accepts multiple values.

.PARAMETER ReplaceCertificateSerialNumber
    When set, ALL existing CertificateSerialNumber authentication entries are deleted
    before the new values in -CertificateSerialNumber are added.

.PARAMETER CertificateSerialNumberComment
    Optional comment applied to every CertificateSerialNumber entry being added.

.PARAMETER CertificateIssuer
    Certificate issuer attribute(s) (e.g. @("CN=Company CA","OU=IT")) for Certificate
    Attributes authentication.

.PARAMETER CertificateSubject
    Certificate subject attribute(s) (e.g. @("CN=app.company.com","OU=IT")) for
    Certificate Attributes authentication.

.PARAMETER CertificateSubjectAlternativeName
    Certificate SAN attribute(s) (e.g. @("DNS Name=www.example.com")) for Certificate
    Attributes authentication.

.PARAMETER ReplaceCertificateAttr
    When set, ALL existing CertificateAttr authentication entries are deleted before the
    new values in -CertificateIssuer/-CertificateSubject/-CertificateSubjectAlternativeName
    are added.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g. https://pvwa.company.com).

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation. Use only for testing with self-signed certificates.

.PARAMETER AuthenticationType
    Authentication type for New-PASSession: cyberark, ldap, or radius. Default: cyberark.

.PARAMETER OTP
    OTP for RADIUS authentication.

.PARAMETER LogonToken
    Existing psPAS session object from Get-PASSession.
    If provided, the script will reuse it and will NOT log off.

.EXAMPLE
    # Add a single Path entry
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" -PVWAUrl "https://pvwa.company.com" `
        -Path "C:\Program Files\MyApp\app.exe"

.EXAMPLE
    # Replace ALL existing Path entries with two new ones
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" -PVWAUrl "https://pvwa.company.com" `
        -Path @("C:\App\v2\app.exe","C:\App\v2\helper.exe") -ReplacePath

.EXAMPLE
    # Replace all existing MachineAddress entries and add new OSUser entries alongside
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" -PVWAUrl "https://pvwa.company.com" `
        -MachineAddress "10.0.0.0/8" -ReplaceMachineAddress `
        -OSUser "DOMAIN\svc_newaccount"

.EXAMPLE
    # Replace all Certificate Attribute entries
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" -PVWAUrl "https://pvwa.company.com" `
        -CertificateSubject @("CN=app.company.com","OU=IT") `
        -CertificateIssuer @("CN=Company Root CA") `
        -ReplaceCertificateAttr
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppID,

    # --- Path ---
    [Parameter(Mandatory = $false)]
    [string[]]$Path,

    [Parameter(Mandatory = $false)]
    [switch]$ReplacePath,

    [Parameter(Mandatory = $false)]
    [bool]$PathIsFolder = $false,

    [Parameter(Mandatory = $false)]
    [bool]$PathAllowInternalScripts = $false,

    # --- Hash ---
    [Parameter(Mandatory = $false)]
    [string[]]$Hash,

    [Parameter(Mandatory = $false)]
    [switch]$ReplaceHash,

    [Parameter(Mandatory = $false)]
    [string]$HashComment,

    # --- OS User ---
    [Parameter(Mandatory = $false)]
    [string[]]$OSUser,

    [Parameter(Mandatory = $false)]
    [switch]$ReplaceOSUser,

    # --- Machine Address ---
    [Parameter(Mandatory = $false)]
    [string[]]$MachineAddress,

    [Parameter(Mandatory = $false)]
    [switch]$ReplaceMachineAddress,

    # --- Certificate Serial Number ---
    [Parameter(Mandatory = $false)]
    [string[]]$CertificateSerialNumber,

    [Parameter(Mandatory = $false)]
    [switch]$ReplaceCertificateSerialNumber,

    [Parameter(Mandatory = $false)]
    [string]$CertificateSerialNumberComment,

    # --- Certificate Attributes ---
    [Parameter(Mandatory = $false)]
    [string[]]$CertificateIssuer,

    [Parameter(Mandatory = $false)]
    [string[]]$CertificateSubject,

    [Parameter(Mandatory = $false)]
    [string[]]$CertificateSubjectAlternativeName,

    [Parameter(Mandatory = $false)]
    [switch]$ReplaceCertificateAttr,

    # --- Connection / Auth ---
    [Parameter(Mandatory = $false)]
    [switch]$DisableCertificateValidation,

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
    [object]$LogonToken
)

#region --- Helper Functions ---

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
    Write-Output ("{0} {1}" -f $Level.ToUpper().PadRight(5), $Message)
}

function Normalize-Scalar {
    param(
        [AllowNull()]
        [string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return $Value.Trim().ToLowerInvariant()
}

function Normalize-StringArray {
    param(
        [AllowNull()]
        [string[]]$Values
    )
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
    $leftNorm  = @(Normalize-StringArray -Values $Left)
    $rightNorm = @(Normalize-StringArray -Values $Right)
    if ($leftNorm.Count -ne $rightNorm.Count) { return $false }
    for ($i = 0; $i -lt $leftNorm.Count; $i++) {
        if ($leftNorm[$i].ToLowerInvariant() -ne $rightNorm[$i].ToLowerInvariant()) {
            return $false
        }
    }
    return $true
}

#endregion

#region --- Initialisation ---

$exitCode           = 0
$shouldLogoff       = $true
$authMethodsToAdd   = @()
$existingAuthMethods = @()
$deletedAuths       = @()
$addedAuths         = @()
$skippedAuths       = @()
$failedAuths        = @()

$PVWAUrl = $PVWAUrl.Trim().TrimEnd('/')
$AppID   = $AppID.Trim()

if (-not [string]::IsNullOrWhiteSpace($OTP)) { $OTP = $OTP.Trim() }

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

# Guard: -Replace<Type> supplied without its companion value parameter
$replaceGuards = @(
    @{ Switch = $ReplacePath;                    Values = $Path;                    Name = '-ReplacePath requires -Path'                                           }
    @{ Switch = $ReplaceHash;                    Values = $Hash;                    Name = '-ReplaceHash requires -Hash'                                           }
    @{ Switch = $ReplaceOSUser;                  Values = $OSUser;                  Name = '-ReplaceOSUser requires -OSUser'                                       }
    @{ Switch = $ReplaceMachineAddress;          Values = $MachineAddress;          Name = '-ReplaceMachineAddress requires -MachineAddress'                       }
    @{ Switch = $ReplaceCertificateSerialNumber; Values = $CertificateSerialNumber; Name = '-ReplaceCertificateSerialNumber requires -CertificateSerialNumber'     }
    @{ Switch = $ReplaceCertificateAttr;         Values = ($CertificateIssuer + $CertificateSubject + $CertificateSubjectAlternativeName); Name = '-ReplaceCertificateAttr requires at least one of -CertificateIssuer, -CertificateSubject, or -CertificateSubjectAlternativeName' }
)

foreach ($guard in $replaceGuards) {
    if ($guard.Switch -and (-not $guard.Values -or $guard.Values.Count -eq 0)) {
        Write-Log 'ERROR' $guard.Name
        exit 1
    }
}

#endregion

#region --- Build Requested Auth Methods List ---

# Path
if ($Path) {
    foreach ($p in $Path) {
        if (-not [string]::IsNullOrWhiteSpace($p)) {
            $authMethodsToAdd += @{
                Type    = 'Path'
                Replace = $ReplacePath.IsPresent
                Object  = @{
                    path                 = $p.Trim()
                    IsFolder             = $PathIsFolder
                    AllowInternalScripts = $PathAllowInternalScripts
                }
            }
        }
    }
}

# Hash
if ($Hash) {
    foreach ($h in $Hash) {
        if (-not [string]::IsNullOrWhiteSpace($h)) {
            $authObj = @{ hash = $h.Trim() }
            if (-not [string]::IsNullOrWhiteSpace($HashComment)) { $authObj['Comment'] = $HashComment.Trim() }
            $authMethodsToAdd += @{
                Type    = 'Hash'
                Replace = $ReplaceHash.IsPresent
                Object  = $authObj
            }
        }
    }
}

# OS User
if ($OSUser) {
    foreach ($user in $OSUser) {
        if (-not [string]::IsNullOrWhiteSpace($user)) {
            $authMethodsToAdd += @{
                Type    = 'OSUser'
                Replace = $ReplaceOSUser.IsPresent
                Object  = @{ osUser = $user.Trim() }
            }
        }
    }
}

# Machine Address
if ($MachineAddress) {
    foreach ($addr in $MachineAddress) {
        if (-not [string]::IsNullOrWhiteSpace($addr)) {
            $authMethodsToAdd += @{
                Type    = 'MachineAddress'
                Replace = $ReplaceMachineAddress.IsPresent
                Object  = @{ machineAddress = $addr.Trim() }
            }
        }
    }
}

# Certificate Serial Number
if ($CertificateSerialNumber) {
    foreach ($serial in $CertificateSerialNumber) {
        if (-not [string]::IsNullOrWhiteSpace($serial)) {
            $authObj = @{ certificateserialnumber = $serial.Trim() }
            if (-not [string]::IsNullOrWhiteSpace($CertificateSerialNumberComment)) { $authObj['Comment'] = $CertificateSerialNumberComment.Trim() }
            $authMethodsToAdd += @{
                Type    = 'CertificateSerialNumber'
                Replace = $ReplaceCertificateSerialNumber.IsPresent
                Object  = $authObj
            }
        }
    }
}

# Certificate Attributes
if ($CertificateIssuer -or $CertificateSubject -or $CertificateSubjectAlternativeName) {
    $authObj = @{}
    $issuerValues  = @(Normalize-StringArray -Values $CertificateIssuer)
    $subjectValues = @(Normalize-StringArray -Values $CertificateSubject)
    $sanValues     = @(Normalize-StringArray -Values $CertificateSubjectAlternativeName)

    if ($issuerValues.Count -gt 0)  { $authObj['Issuer']                    = $issuerValues  }
    if ($subjectValues.Count -gt 0) { $authObj['Subject']                   = $subjectValues }
    if ($sanValues.Count -gt 0)     { $authObj['SubjectAlternativeName']     = $sanValues     }

    $authMethodsToAdd += @{
        Type    = 'CertificateAttr'
        Replace = $ReplaceCertificateAttr.IsPresent
        Object  = $authObj
    }
}

#endregion

#region --- Module Check ---

if (-not (Get-Module -ListAvailable -Name psPAS)) {
    Write-Log 'ERROR' 'psPAS module is not installed or not available.'
    exit 1
}

Import-Module psPAS -ErrorAction Stop

#endregion

#region --- Authentication ---

if ($null -ne $LogonToken) {
    try {
        Use-PASSession -Session $LogonToken
        $shouldLogoff = $false
        Write-Log 'INFO' 'Using provided psPAS session. Script will not log off.'
    } catch {
        Write-Log 'ERROR' ("Could not use provided psPAS session: {0}" -f $_.Exception.Message)
        exit 1
    }
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

    if ($DisableCertificateValidation) { $sessionParams['SkipCertificateCheck'] = $true }
    if ($AuthenticationType -eq 'radius') { $sessionParams['OTP'] = $OTP }

    try {
        $null = New-PASSession @sessionParams
        Write-Log 'INFO' 'Authentication successful.'
    } catch {
        Write-Log 'ERROR' ("Authentication failed: {0}" -f $_.Exception.Message)
        exit 1
    }
}

#endregion

#region --- Validate Application Exists ---

Write-Log 'INFO' ("Validating application '{0}' exists..." -f $AppID)

try {
    $null = Get-PASApplication -AppID $AppID -ExactMatch
    Write-Log 'INFO' ("Application '{0}' verified." -f $AppID)
} catch {
    Write-Log 'ERROR' ("Could not validate application '{0}': {1}" -f $AppID, $_.Exception.Message)
    $exitCode = 1
}

#endregion

#region --- Verify-Only Mode ---

if ($exitCode -eq 0 -and $authMethodsToAdd.Count -eq 0) {
    Write-Log 'INFO' 'No authentication methods were specified. Verification only completed successfully.'
}

#endregion

#region --- Retrieve Existing Auth Methods ---

if ($exitCode -eq 0 -and $authMethodsToAdd.Count -gt 0) {
    Write-Log 'INFO' ("Retrieving existing authentication methods for application '{0}'..." -f $AppID)

    try {
        $result = Get-PASApplicationAuthenticationMethod -AppID $AppID
        $existingAuthMethods = if ($null -ne $result) { @($result) } else { @() }
        Write-Log 'INFO' ("Found {0} existing authentication method(s)." -f $existingAuthMethods.Count)
    } catch {
        Write-Log 'ERROR' ("Could not retrieve existing authentication methods: {0}" -f $_.Exception.Message)
        $exitCode = 1
    }
}

#endregion

#region --- Delete Phase (Replace switches) ---
#
# For each type that has a Replace switch set, delete ALL existing entries of that type
# before any adds are attempted. Each type is only purged once even if multiple values
# of that type are in $authMethodsToAdd.

if ($exitCode -eq 0 -and $authMethodsToAdd.Count -gt 0) {

    # Collect the unique types that need replacing
    $typesToReplace = $authMethodsToAdd |
        Where-Object { $_.Replace -eq $true } |
        Select-Object -ExpandProperty Type -Unique

    foreach ($replaceType in $typesToReplace) {

        # Normalised API AuthType string as returned by Get-PASApplicationAuthenticationMethod
        $apiTypeLower = $replaceType.ToLowerInvariant()

        $toDelete = $existingAuthMethods | Where-Object {
            (Normalize-Scalar $_.AuthType) -eq $apiTypeLower
        }

        if (-not $toDelete -or @($toDelete).Count -eq 0) {
            Write-Log 'INFO' ("Replace requested for type '{0}' but no existing entries found — nothing to delete." -f $replaceType)
            continue
        }

        foreach ($entry in @($toDelete)) {
            $authID       = $entry.authID
            $displayValue = if ($entry.AuthValue) { $entry.AuthValue } else { "(Certificate Attributes ID: $authID)" }

            Write-Log 'INFO' ("Deleting existing {0} authentication entry (AuthID: {1}, Value: {2})..." -f $replaceType, $authID, $displayValue)

            try {
                Remove-PASApplicationAuthenticationMethod -AppID $AppID -AuthID $authID
                $deletedAuths += ("{0}: {1} (AuthID: {2})" -f $replaceType, $displayValue, $authID)
                Write-Log 'INFO' ("Deleted {0} authentication entry (AuthID: {1})." -f $replaceType, $authID)
            } catch {
                Write-Log 'ERROR' ("Failed to delete {0} authentication entry (AuthID: {1}): {2}" -f $replaceType, $authID, $_.Exception.Message)
                $failedAuths += ("DELETE {0}: {1} - {2}" -f $replaceType, $displayValue, $_.Exception.Message)
                $exitCode = 1
            }
        }

        # Refresh the in-memory list so the add-phase duplicate check reflects deletions
        if ($exitCode -eq 0) {
            $existingAuthMethods = $existingAuthMethods | Where-Object {
                (Normalize-Scalar $_.AuthType) -ne $apiTypeLower
            }
            if ($null -eq $existingAuthMethods) { $existingAuthMethods = @() }
        }
    }
}

#endregion

#region --- Add Phase ---

if ($exitCode -eq 0 -and $authMethodsToAdd.Count -gt 0) {

    foreach ($authMethod in $authMethodsToAdd) {
        $authType    = $authMethod.Type
        $authObj     = $authMethod.Object
        $isDuplicate = $false

        # Friendly display value for log messages
        $displayValue = switch ($authType) {
            'Path'                  { $authObj.path }
            'Hash'                  { $authObj.hash }
            'OSUser'                { $authObj.osUser }
            'MachineAddress'        { $authObj.machineAddress }
            'CertificateSerialNumber' { $authObj.certificateserialnumber }
            default                 { 'Certificate Attributes' }
        }

        # Duplicate check against (already-updated) $existingAuthMethods
        foreach ($existing in $existingAuthMethods) {
            $existingTypeLower = Normalize-Scalar $existing.AuthType

            if ($authType -eq 'CertificateAttr' -and $existingTypeLower -eq 'certificateattr') {
                $existingSubject = if ($existing.Subject) { @($existing.Subject) } else { @() }
                $existingIssuer  = if ($existing.Issuer)  { @($existing.Issuer)  } else { @() }
                $existingSAN     = if ($existing.SubjectAlternativeName) { @($existing.SubjectAlternativeName) } else { @() }

                if ((Compare-NormalizedStringArrays -Left $authObj.Subject -Right $existingSubject) -and
                    (Compare-NormalizedStringArrays -Left $authObj.Issuer  -Right $existingIssuer)  -and
                    (Compare-NormalizedStringArrays -Left $authObj.SubjectAlternativeName -Right $existingSAN)) {
                    $isDuplicate = $true
                    break
                }
            } else {
                $matchMap = @{
                    'Path'                    = @{ ApiType = 'path';                    Key = 'path'                    }
                    'Hash'                    = @{ ApiType = 'hash';                    Key = 'hash'                    }
                    'OSUser'                  = @{ ApiType = 'osuser';                  Key = 'osUser'                  }
                    'MachineAddress'          = @{ ApiType = 'machineaddress';          Key = 'machineAddress'          }
                    'CertificateSerialNumber' = @{ ApiType = 'certificateserialnumber'; Key = 'certificateserialnumber' }
                }

                if ($matchMap.ContainsKey($authType)) {
                    $map = $matchMap[$authType]
                    if ($existingTypeLower -eq $map.ApiType -and
                        (Normalize-Scalar $existing.AuthValue) -eq (Normalize-Scalar $authObj[$map.Key])) {
                        $isDuplicate = $true
                        break
                    }
                }
            }
        }

        if ($isDuplicate) {
            $skippedAuths += ("{0}: {1} (duplicate)" -f $authType, $displayValue)
            Write-Log 'INFO' ("Skipping {0} authentication — already exists: {1}" -f $authType, $displayValue)
            continue
        }

        # Add the entry
        try {
            Write-Log 'INFO' ("Adding {0} authentication: {1}" -f $authType, $displayValue)

            switch ($authType) {
                'Path' {
                    $null = Add-PASApplicationAuthenticationMethod -AppID $AppID `
                        -path $authObj.path `
                        -IsFolder $authObj.IsFolder `
                        -AllowInternalScripts $authObj.AllowInternalScripts
                }
                'Hash' {
                    if ($authObj.ContainsKey('Comment')) {
                        $null = Add-PASApplicationAuthenticationMethod -AppID $AppID -hash $authObj.hash -Comment $authObj.Comment
                    } else {
                        $null = Add-PASApplicationAuthenticationMethod -AppID $AppID -hash $authObj.hash
                    }
                }
                'OSUser' {
                    $null = Add-PASApplicationAuthenticationMethod -AppID $AppID -osUser $authObj.osUser
                }
                'MachineAddress' {
                    $null = Add-PASApplicationAuthenticationMethod -AppID $AppID -machineAddress $authObj.machineAddress
                }
                'CertificateSerialNumber' {
                    if ($authObj.ContainsKey('Comment')) {
                        $null = Add-PASApplicationAuthenticationMethod -AppID $AppID -certificateserialnumber $authObj.certificateserialnumber -Comment $authObj.Comment
                    } else {
                        $null = Add-PASApplicationAuthenticationMethod -AppID $AppID -certificateserialnumber $authObj.certificateserialnumber
                    }
                }
                'CertificateAttr' {
                    $addAttrParams = @{ AppID = $AppID }
                    if ($authObj.ContainsKey('Subject'))                { $addAttrParams['Subject']                   = $authObj.Subject                   }
                    if ($authObj.ContainsKey('Issuer'))                 { $addAttrParams['Issuer']                    = $authObj.Issuer                    }
                    if ($authObj.ContainsKey('SubjectAlternativeName')) { $addAttrParams['SubjectAlternativeName']     = $authObj.SubjectAlternativeName     }
                    $null = Add-PASApplicationAuthenticationMethod @addAttrParams
                }
            }

            $addedAuths += ("{0}: {1}" -f $authType, $displayValue)
            Write-Log 'INFO' ("Successfully added {0} authentication: {1}" -f $authType, $displayValue)

        } catch {
            $failedAuths += ("ADD {0}: {1} - {2}" -f $authType, $displayValue, $_.Exception.Message)
            Write-Log 'ERROR' ("Failed to add {0} authentication '{1}': {2}" -f $authType, $displayValue, $_.Exception.Message)
        }
    }
}

#endregion

#region --- Summary ---

Write-Output ''
Write-Output ('=' * 80)
Write-Output 'SUMMARY'
Write-Output ('=' * 80)

if ($deletedAuths.Count -gt 0) {
    Write-Output ''
    Write-Log 'INFO' ("Deleted {0} authentication method(s) (replace operation):" -f $deletedAuths.Count)
    foreach ($auth in $deletedAuths) { Write-Output ("  - {0}" -f $auth) }
}

if ($addedAuths.Count -gt 0) {
    Write-Output ''
    Write-Log 'INFO' ("Added {0} authentication method(s):" -f $addedAuths.Count)
    foreach ($auth in $addedAuths) { Write-Output ("  - {0}" -f $auth) }
}

if ($skippedAuths.Count -gt 0) {
    Write-Output ''
    Write-Log 'INFO' ("Skipped {0} authentication method(s):" -f $skippedAuths.Count)
    foreach ($auth in $skippedAuths) { Write-Output ("  - {0}" -f $auth) }
}

if ($failedAuths.Count -gt 0) {
    Write-Output ''
    Write-Log 'ERROR' ("Failed {0} authentication method(s):" -f $failedAuths.Count)
    foreach ($auth in $failedAuths) { Write-Output ("  - {0}" -f $auth) }
    $exitCode = 1
}

#endregion

#region --- Display Final Auth Method List ---

if ($exitCode -eq 0 -and ($addedAuths.Count -gt 0 -or $deletedAuths.Count -gt 0)) {
    Write-Log 'INFO' 'Retrieving final authentication methods...'

    try {
        $finalMethods = Get-PASApplicationAuthenticationMethod -AppID $AppID

        if ($finalMethods) {
            $finalMethods = @($finalMethods)
            Write-Output ''
            Write-Log 'INFO' ("Application '{0}' now has {1} authentication method(s):" -f $AppID, $finalMethods.Count)
            Write-Output ('=' * 80)

            foreach ($auth in $finalMethods) {
                Write-Output ("  - AuthID: {0} | Type: {1}" -f $auth.authID, $auth.AuthType)
                if ($auth.AuthValue)                 { Write-Output ("    Value                  : {0}" -f $auth.AuthValue) }
                if ($auth.Subject)                   { Write-Output ("    Subject                : {0}" -f (@($auth.Subject) -join '; ')) }
                if ($auth.Issuer)                    { Write-Output ("    Issuer                 : {0}" -f (@($auth.Issuer) -join '; ')) }
                if ($auth.SubjectAlternativeName)    { Write-Output ("    SubjectAlternativeName : {0}" -f (@($auth.SubjectAlternativeName) -join '; ')) }
                if ($auth.Comment)                   { Write-Output ("    Comment                : {0}" -f $auth.Comment) }
                if ($null -ne $auth.IsFolder)        { Write-Output ("    IsFolder               : {0}" -f $auth.IsFolder) }
                if ($null -ne $auth.AllowInternalScripts) { Write-Output ("    AllowInternalScripts   : {0}" -f $auth.AllowInternalScripts) }
            }

            Write-Output ('=' * 80)
        }
    } catch {
        Write-Log 'WARN' ("Could not retrieve final authentication methods: {0}" -f $_.Exception.Message)
    }
}

#endregion

#region --- Session Cleanup ---

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
