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
$authMethods = @()
$authToDelete = $null
$authMethodsAfterDelete = @()

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

if ($AuthID -lt 1) {
    Write-Log 'ERROR' 'AuthID must be greater than 0.'
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

# Retrieve authentication methods
if ($exitCode -eq 0) {
    Write-Log 'INFO' ("Retrieving authentication methods for application '{0}'..." -f $AppID)

    try {
        $result = Get-PASApplicationAuthenticationMethod -AppID $AppID
        if ($null -ne $result) {
            $authMethods = @($result)
        } else {
            $authMethods = @()
        }
    } catch {
        Write-Log 'ERROR' ("Could not retrieve authentication methods for application '{0}': {1}" -f $AppID, $_.Exception.Message)
        $exitCode = 1
    }
}

# Find requested authentication by AuthID
if ($exitCode -eq 0) {
    if ($authMethods.Count -eq 0) {
        Write-Log 'ERROR' ("No authentication methods were found for application '{0}'." -f $AppID)
        $exitCode = 1
    } else {
        $matches = @($authMethods | Where-Object { [string]$_.authID -eq [string]$AuthID })

        if ($matches.Count -eq 0) {
            Write-Log 'ERROR' ("Authentication with AuthID {0} not found for application '{1}'." -f $AuthID, $AppID)
            $exitCode = 1
        } elseif ($matches.Count -gt 1) {
            Write-Log 'ERROR' ("Multiple authentication records were returned for AuthID {0} on application '{1}'." -f $AuthID, $AppID)
            $exitCode = 1
        } else {
            $authToDelete = $matches[0]
        }
    }
}

# Display authentication selected for deletion
if ($exitCode -eq 0 -and $null -ne $authToDelete) {
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
}

# Confirm deletion
if ($exitCode -eq 0) {
    $confirmation = Read-Host "Are you sure you want to delete this authentication? Type yes to continue"
    if ($confirmation -ne 'yes') {
        Write-Log 'WARN' 'Deletion cancelled by user.'
        exit 1
    }
}

# Delete authentication method
if ($exitCode -eq 0) {
    Write-Log 'INFO' ("Deleting authentication AuthID {0} from application '{1}'..." -f $AuthID, $AppID)

    try {
        $null = Remove-PASApplicationAuthenticationMethod -AppID $AppID -AuthID ([string]$AuthID) -Confirm:$false
        Write-Log 'INFO' ("Authentication AuthID {0} was deleted from application '{1}'." -f $AuthID, $AppID)
    } catch {
        Write-Log 'ERROR' ("Could not delete authentication AuthID {0} from application '{1}': {2}" -f $AuthID, $AppID, $_.Exception.Message)
        $exitCode = 1
    }
}

# Verify deletion
if ($exitCode -eq 0) {
    Write-Log 'INFO' 'Verifying authentication was deleted...'

    try {
        $result = Get-PASApplicationAuthenticationMethod -AppID $AppID
        if ($null -ne $result) {
            $authMethodsAfterDelete = @($result)
        } else {
            $authMethodsAfterDelete = @()
        }
    } catch {
        Write-Log 'ERROR' ("Could not verify deletion for application '{0}': {1}" -f $AppID, $_.Exception.Message)
        $exitCode = 1
    }

    if ($exitCode -eq 0) {
        $stillExists = @($authMethodsAfterDelete | Where-Object { [string]$_.authID -eq [string]$AuthID })

        if ($stillExists.Count -eq 0) {
            Write-Log 'INFO' ("Confirmed: Authentication AuthID {0} no longer exists." -f $AuthID)
        } else {
            Write-Log 'WARN' ("Authentication AuthID {0} still appears to exist." -f $AuthID)
            $exitCode = 1
        }
    }
}

# Display remaining authentication methods
if ($exitCode -eq 0) {
    if ($authMethodsAfterDelete.Count -gt 0) {
        Write-Output ''
        Write-Output ("Remaining authentication method(s) for application '{0}': {1}" -f $AppID, $authMethodsAfterDelete.Count)
        Write-Output ('=' * 80)

        foreach ($auth in $authMethodsAfterDelete) {
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
