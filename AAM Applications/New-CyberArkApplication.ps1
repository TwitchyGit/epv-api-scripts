<#
.SYNOPSIS
    Adds a new application to CyberArk using psPAS, with support for CCP and CP application types.

.DESCRIPTION
    This script authenticates with psPAS and creates a new application in the Vault.

    ApplicationType behaviour:
      AddCCP  - Prefixes AppID with 'cp_ccp_', sets Location to \CCPApplications, no expiry.
                No vault account is onboarded.
      AddCP   - Prefixes AppID with 'cs_cp_', sets Location to \CPApplications, no expiry.
                A vault account is onboarded into the safe specified by -SafeName, using a
                randomly generated 25-character password (alphanumeric with '-' separators).

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g. https://pvwa.company.com/PasswordVault)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER ApplicationType
    Required. Either 'AddCCP' or 'AddCP'. Controls the prefix, location, and whether a
    vault account is onboarded.

.PARAMETER AppID
    The application name without prefix (required). The appropriate prefix is prepended
    automatically based on ApplicationType.

.PARAMETER Description
    Optional description of the application.

.PARAMETER SafeName
    Required when ApplicationType is AddCP. The safe into which the vault account is onboarded.

.PARAMETER AccessPermittedFrom
    Optional start hour that access is permitted (0-23).

.PARAMETER AccessPermittedTo
    Optional end hour that access is permitted (0-23).

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
    Existing psPAS session object from Get-PASSession.
    If provided, the script will reuse it and will NOT log off.

.EXAMPLE
    $cred = Get-Credential
    .\New-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com/PasswordVault" `
        -Credential $cred `
        -ApplicationType AddCCP `
        -AppID "MyNewApp" `
        -Description "My CCP application"

.EXAMPLE
    .\New-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com/PasswordVault" `
        -ApplicationType AddCP `
        -AppID "MyNewApp" `
        -SafeName "CP_Applications_Safe" `
        -BusinessOwnerFName "John" `
        -BusinessOwnerLName "Doe" `
        -BusinessOwnerEmail "john.doe@company.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('AddCCP', 'AddCP')]
    [string]$ApplicationType,

    [Parameter(Mandatory = $true)]
    [string]$AppID,

    [Parameter(Mandatory = $false)]
    [string]$Description,

    [Parameter(Mandatory = $false)]
    [string]$SafeName,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 23)]
    [int]$AccessPermittedFrom,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 23)]
    [int]$AccessPermittedTo,

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

function New-RandomPassword {
    <#
    .SYNOPSIS
        Generates a 25-character random password of alphanumeric characters with a '-'
        separator inserted after every 5th or 6th character (alternating), producing a
        grouped format such as: aBcD3-xYz12-mNpQ7-rStU4-vW9

    .OUTPUTS
        [string] The generated password.
    #>

    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    # Build 25 cryptographically random alphanumeric characters
    $rawChars = [System.Text.StringBuilder]::new(25)
    $singleByte = [byte[]]::new(1)

    while ($rawChars.Length -lt 25) {
        $rng.GetBytes($singleByte)
        # Rejection sampling: discard values that would create modulo bias
        $index = $singleByte[0] % $chars.Length
        if ($singleByte[0] -lt (256 - (256 % $chars.Length))) {
            $null = $rawChars.Append($chars[$index])
        }
    }

    $rng.Dispose()

    # Insert '-' separators: groups of 5, 6, 5, 6, 3 = 25 chars -> "XXXXX-XXXXXX-XXXXX-XXXXXX-XXX"
    # Pattern alternates 5/6 to produce a natural-looking grouped password
    $groupSizes = @(5, 6, 5, 6, 3)
    $password   = [System.Text.StringBuilder]::new(30)
    $pos        = 0

    for ($i = 0; $i -lt $groupSizes.Length; $i++) {
        if ($i -gt 0) { $null = $password.Append('-') }
        $null = $password.Append($rawChars.ToString().Substring($pos, $groupSizes[$i]))
        $pos += $groupSizes[$i]
    }

    return $password.ToString()
}

#endregion

#region --- Type-Driven Configuration ---

switch ($ApplicationType) {
    'AddCCP' {
        $appPrefix      = 'cp_ccp_'
        $targetLocation = '\CCPApplications'
        $onboardAccount = $false
    }
    'AddCP' {
        $appPrefix      = 'cs_cp_'
        $targetLocation = '\CPApplications'
        $onboardAccount = $true
    }
}

#endregion

#region --- Pre-flight Validation ---

$exitCode    = 0
$shouldLogoff = $true

# Normalize string inputs
$PVWAUrl = $PVWAUrl.Trim().TrimEnd('/')
$AppID   = $AppID.Trim()

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

# AddCP requires a SafeName for account onboarding
if ($onboardAccount -and [string]::IsNullOrWhiteSpace($SafeName)) {
    Write-Log 'ERROR' 'SafeName is required when ApplicationType is AddCP.'
    exit 1
}

if ($AuthenticationType -eq 'radius' -and [string]::IsNullOrWhiteSpace($OTP)) {
    Write-Log 'ERROR' 'OTP is required when AuthenticationType is radius.'
    exit 1
}

# Build the full prefixed AppID
# Strip any accidental prefix duplication if the caller included it
$cleanAppID = $AppID -replace "^$([regex]::Escape($appPrefix))", ''
$fullAppID  = '{0}{1}' -f $appPrefix, $cleanAppID

Write-Log 'INFO' ("ApplicationType : {0}" -f $ApplicationType)
Write-Log 'INFO' ("Resolved AppID  : {0}" -f $fullAppID)
Write-Log 'INFO' ("Location        : {0}" -f $targetLocation)

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

#region --- Duplicate Check ---

Write-Log 'INFO' ("Checking if application '{0}' already exists..." -f $fullAppID)

$existingApp = $null
try {
    $existingApp = Get-PASApplication -AppID $fullAppID -ExactMatch
} catch {
    $existingApp = $null
}

if ($existingApp) {
    Write-Log 'ERROR' ("Application '{0}' already exists. Use a different name or delete the existing application first." -f $fullAppID)
    $exitCode = 1
}

#endregion

#region --- Create Application ---

if ($exitCode -eq 0) {
    $addParams = @{
        AppID    = $fullAppID
        Location = $targetLocation
        Disabled = $Disabled
        # ExpirationDate is intentionally omitted so the application never expires
    }

    if (-not [string]::IsNullOrWhiteSpace($Description))        { $addParams['Description']        = $Description.Trim() }
    if ($PSBoundParameters.ContainsKey('AccessPermittedFrom'))  { $addParams['AccessPermittedFrom'] = $AccessPermittedFrom }
    if ($PSBoundParameters.ContainsKey('AccessPermittedTo'))    { $addParams['AccessPermittedTo']   = $AccessPermittedTo }
    if (-not [string]::IsNullOrWhiteSpace($BusinessOwnerFName)) { $addParams['BusinessOwnerFName']  = $BusinessOwnerFName.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($BusinessOwnerLName)) { $addParams['BusinessOwnerLName']  = $BusinessOwnerLName.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($BusinessOwnerEmail)) { $addParams['BusinessOwnerEmail']  = $BusinessOwnerEmail.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($BusinessOwnerPhone)) { $addParams['BusinessOwnerPhone']  = $BusinessOwnerPhone.Trim() }

    Write-Log 'INFO' ("Creating application '{0}'..." -f $fullAppID)

    try {
        $null = Add-PASApplication @addParams
        Write-Log 'INFO' ("Application '{0}' created successfully." -f $fullAppID)
    } catch {
        Write-Log 'ERROR' ("Could not create application '{0}': {1}" -f $fullAppID, $_.Exception.Message)
        $exitCode = 1
    }
}

#endregion

#region --- Onboard Vault Account (AddCP only) ---

$generatedPassword = $null

if ($exitCode -eq 0 -and $onboardAccount) {
    Write-Log 'INFO' ("Generating vault account password for '{0}'..." -f $fullAppID)

    $generatedPassword = New-RandomPassword

    # Convert to SecureString for Add-PASAccount
    $securePassword = ConvertTo-SecureString -String $generatedPassword -AsPlainText -Force

    Write-Log 'INFO' ("Onboarding vault account for '{0}' into safe '{1}'..." -f $fullAppID, $SafeName.Trim())

    $accountParams = @{
        SafeName               = $SafeName.Trim()
        PlatformID             = 'WinLocalAdministrator'   # adjust to your target platform
        Address                = 'localhost'                # adjust to your target address
        Username               = $fullAppID
        Secret                 = $securePassword
        SecretType             = 'Password'
        # platformAccountProperties can carry PasswordNeverExpires if your platform supports it
        platformAccountProperties = @{
            PasswordNeverExpires = 'True'
        }
    }

    # Use the friendly account name so it is identifiable in the safe
    $accountParams['Name'] = $fullAppID

    try {
        $newAccount = Add-PASAccount @accountParams
        Write-Log 'INFO' ("Vault account '{0}' onboarded successfully (AccountID: {1})." -f $fullAppID, $newAccount.id)
    } catch {
        Write-Log 'ERROR' ("Could not onboard vault account for '{0}': {1}" -f $fullAppID, $_.Exception.Message)
        $exitCode = 1
    }

    # Scrub the SecureString from memory
    $securePassword.Dispose()
}

#endregion

#region --- Verification Display ---

if ($exitCode -eq 0) {
    Write-Log 'INFO' 'Verifying application was created...'

    $verifiedApp = $null
    try {
        $verifiedApp = Get-PASApplication -AppID $fullAppID -ExactMatch
    } catch {
        $verifiedApp = $null
        Write-Log 'WARN' ("Application '{0}' was created but could not be re-read for display: {1}" -f $fullAppID, $_.Exception.Message)
    }

    if ($null -ne $verifiedApp) {
        Write-Output ''
        Write-Output 'Application Details:'
        Write-Output ('=' * 80)
        Write-Output ("  AppID            : {0}" -f $verifiedApp.AppID)
        Write-Output ("  ApplicationType  : {0}" -f $ApplicationType)

        if ($verifiedApp.Description) {
            Write-Output ("  Description      : {0}" -f $verifiedApp.Description)
        }

        if ($verifiedApp.Location) {
            Write-Output ("  Location         : {0}" -f $verifiedApp.Location)
        }

        Write-Output ("  Disabled         : {0}" -f $verifiedApp.Disabled)
        Write-Output ("  Expiration       : Never")

        if ($null -ne $verifiedApp.AccessPermittedFrom -or $null -ne $verifiedApp.AccessPermittedTo) {
            Write-Output ("  Access Hours     : {0} - {1}" -f $verifiedApp.AccessPermittedFrom, $verifiedApp.AccessPermittedTo)
        }

        if ($verifiedApp.BusinessOwnerFName -or $verifiedApp.BusinessOwnerLName) {
            Write-Output ("  Business Owner   : {0} {1}" -f $verifiedApp.BusinessOwnerFName, $verifiedApp.BusinessOwnerLName)
        }

        if ($verifiedApp.BusinessOwnerEmail) {
            Write-Output ("  Business Owner   : {0}" -f $verifiedApp.BusinessOwnerEmail)
        }

        if ($verifiedApp.BusinessOwnerPhone) {
            Write-Output ("  Business Owner   : {0}" -f $verifiedApp.BusinessOwnerPhone)
        }

        if ($onboardAccount) {
            Write-Output ("  Vault Account    : {0} (onboarded into safe: {1})" -f $fullAppID, $SafeName.Trim())
            Write-Output ("  Password Expires : Never")
        }

        Write-Output ('=' * 80)
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

# Scrub sensitive references
$Credential        = $null
$generatedPassword = $null

exit $exitCode
