<#
.SYNOPSIS
    Creates the Prov_<server> CCP user in CyberArk using psPAS.

.DESCRIPTION
    This script authenticates with psPAS and creates a CCP provider user named
    Prov_<server> in the Vault.

    The user is created:
    - In location \Applications
    - With user type AppProvider
    - With vault authorization AuditUsers

.PARAMETER ServerName
    The server name used to build the CCP provider user name.
    The created user name will be Prov_<server>.

.PARAMETER InitialPassword
    Initial password for the new user as a SecureString.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g. https://pvwa.company.com)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation. Use only for testing with self-signed certificates.

.PARAMETER AuthenticationType
    Authentication type for New-PASSession.

.PARAMETER OTP
    OTP for RADIUS authentication.

.PARAMETER LogonToken
    Pass an existing psPAS session object. If passed the session is NOT logged off.

.EXAMPLE
    $cred = Get-Credential
    $pwd = Read-Host "Enter initial password" -AsSecureString

    .\New-CCPProviderUser.ps1 `
        -PVWAUrl "https://pvwa.company.com" `
        -Credential $cred `
        -ServerName "server01" `
        -InitialPassword $pwd

.EXAMPLE
    $pwd = Read-Host "Enter initial password" -AsSecureString

    .\New-CCPProviderUser.ps1 `
        -PVWAUrl "https://pvwa.company.com" `
        -ServerName "app01" `
        -InitialPassword $pwd
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,

    [Parameter(Mandatory = $true)]
    [System.Security.SecureString]$InitialPassword,

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

    # Simple script-friendly logging
    Write-Output ("{0} {1}" -f $Level.ToUpper().PadRight(5), $Message)
}

$exitCode = 0
$shouldLogoff = $true
$userName = $null
$existingUser = $null
$newUser = $null
$verifiedUser = $null

# Normalize string inputs once at the start
$PVWAUrl = $PVWAUrl.Trim().TrimEnd('/')
$ServerName = $ServerName.Trim()

if (-not [string]::IsNullOrWhiteSpace($OTP)) {
    $OTP = $OTP.Trim()
}

# Build CCP provider user name
$userName = "Prov_{0}" -f $ServerName

# Basic validation
if ([string]::IsNullOrWhiteSpace($ServerName)) {
    Write-Log 'ERROR' 'ServerName cannot be blank.'
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

if ($null -eq $InitialPassword) {
    Write-Log 'ERROR' 'InitialPassword is required.'
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
    # Prompt for credentials if not provided
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

# Check whether the user already exists
Write-Log 'INFO' ("Checking if user '{0}' already exists..." -f $userName)

try {
    $existingUser = Get-PASUser -UserName $userName
} catch {
    $existingUser = $null
}

if ($existingUser) {
    Write-Log 'ERROR' ("User '{0}' already exists. Use a different server name or delete the existing user first." -f $userName)
    $exitCode = 1
}

# Prepare and create the CCP provider user
if ($exitCode -eq 0) {
    $newUserParams = @{
        UserName           = $userName
        InitialPassword    = $InitialPassword
        userType           = 'AppProvider'
        Location           = '\Applications'
        vaultAuthorization = @('AuditUsers')
    }

    Write-Log 'INFO' ("Creating CCP provider user '{0}'..." -f $userName)

    try {
        $newUser = New-PASUser @newUserParams
        Write-Log 'INFO' ("User '{0}' created successfully." -f $userName)
    } catch {
        Write-Log 'ERROR' ("Could not create user '{0}': {1}" -f $userName, $_.Exception.Message)
        $exitCode = 1
    }
}

# Verify the user was created
if ($exitCode -eq 0) {
    Write-Log 'INFO' 'Verifying user was created...'

    try {
        $verifiedUser = Get-PASUser -UserName $userName
    } catch {
        $verifiedUser = $null
        Write-Log 'WARN' ("User '{0}' was created but could not be re-read for display: {1}" -f $userName, $_.Exception.Message)
    }

    # Display the user details
    if ($null -ne $verifiedUser) {
        Write-Output ''
        Write-Output 'User Details:'
        Write-Output ('=' * 80)
        Write-Output ("  UserName: {0}" -f $verifiedUser.username)

        if ($verifiedUser.userType) {
            Write-Output ("  UserType: {0}" -f $verifiedUser.userType)
        }

        if ($verifiedUser.location) {
            Write-Output ("  Location: {0}" -f $verifiedUser.location)
        }

        if ($null -ne $verifiedUser.enableUser) {
            Write-Output ("  Enabled: {0}" -f $verifiedUser.enableUser)
        }

        if ($verifiedUser.vaultAuthorization) {
            Write-Output ("  Vault Authorization: {0}" -f (@($verifiedUser.vaultAuthorization) -join ', '))
        }

        Write-Output ('=' * 80)
    } else {
        Write-Log 'WARN' ("User '{0}' was created but could not be re-read for display." -f $userName)
    }
}

# Log off only if this script created the session
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

# Clear sensitive references
$Credential = $null
$InitialPassword = $null

exit $exitCode
