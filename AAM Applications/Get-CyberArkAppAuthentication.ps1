<#
.SYNOPSIS
    Retrieves authentication methods for a CyberArk Application.

.DESCRIPTION
    This script authenticates to CyberArk via psPAS and retrieves all authentication
    methods configured for a specified application.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g., https://pvwa.company.com)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER AppID
    The Application ID to retrieve authentication methods for

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation. Use only for testing with self-signed certificates.

.EXAMPLE
    $cred = Get-Credential
    .\Get-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
        -Credential $cred `
        -AppID "MyApp"

.EXAMPLE
    .\Get-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
        -AppID "MyApp"
    # Credentials will be prompted if not provided
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

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the Authentication type (Default:CyberArk)')]
    [ValidateSet('cyberark', 'ldap', 'radius')]
    [String]$AuthenticationType = 'cyberark',

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the RADIUS OTP')]
    [String]$OTP,

    [Parameter(Mandatory = $false, HelpMessage = 'Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off')]
    [Alias('session', 'sessionToken')]
    $logonToken
)

# Set TLS to 1.2 or higher
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Check if session token was provided
$shouldLogoff = $true
if ($logonToken) {
    Write-Output 'Using provided session token...'
    Use-PASSession $logonToken
    $shouldLogoff = $false
    Write-Output 'Session token accepted. Will NOT log off at end.'
} else {
    # Prompt for credentials if not provided
    if (-not $Credential) {
        $Credential = Get-Credential -Message 'Enter CyberArk credentials'
        if (-not $Credential) {
            throw 'Credentials are required to proceed.'
        }
    }

    Write-Output "Authenticating to CyberArk using $AuthenticationType..."

    # Build New-PASSession parameters
    $sessionParams = @{
        BaseURI            = $PVWAUrl
        Credential         = $Credential
        type               = $AuthenticationType
        concurrentSession  = $true
    }

    if ($DisableCertificateValidation) {
        Write-Warning "Certificate validation is disabled. This should only be used for testing!"
        $sessionParams['SkipCertificateCheck'] = $true
    }

    # Add RADIUS OTP if provided
    if ($AuthenticationType -eq 'radius' -and $OTP) {
        $sessionParams['OTP']         = $OTP
        $sessionParams['OTPMode']     = 'append'
    }
}

try {
    if ($shouldLogoff) {
        New-PASSession @sessionParams
        Write-Output 'Authentication successful!'
    }

    # Retrieve authentication methods
    Write-Output "`nRetrieving authentication methods for application '$AppID'..."

    $authMethods = Get-PASApplicationAuthenticationMethod -AppID $AppID
    Write-Verbose ($authMethods | ConvertTo-Json -Depth 5)

    # Display all authentication methods
    if ($authMethods) {
        $methodList = @($authMethods)
        Write-Output "`nFound $($methodList.Count) authentication method(s) for application '$AppID':"

        foreach ($auth in $methodList) {
            Write-Output "`n  - Auth ID: $($auth.authID) | Type: $($auth.AuthType)"

            if ($auth.AuthValue) {
                Write-Output "    AuthValue: $($auth.AuthValue)"
            }
            if ($auth.Subject) {
                Write-Output "    Subject: $($auth.Subject -join ', ')"
            }
            if ($auth.Issuer) {
                Write-Output "    Issuer: $($auth.Issuer -join ', ')"
            }
            if ($auth.SubjectAlternativeName) {
                Write-Output "    SubjectAlternativeName: $($auth.SubjectAlternativeName -join ', ')"
            }
            if ($auth.Comment) {
                Write-Output "    Comment: $($auth.Comment)"
            }
            if ($null -ne $auth.IsFolder) {
                Write-Output "    IsFolder: $($auth.IsFolder)"
            }
            if ($null -ne $auth.AllowInternalScripts) {
                Write-Output "    AllowInternalScripts: $($auth.AllowInternalScripts)"
            }
        }

        Write-Output ''
    } else {
        Write-Output "`nNo authentication methods found for application '$AppID'."
    }

    # Logoff (only if we authenticated in this script)
    if ($shouldLogoff) {
        Write-Output 'Logging off...'
        Close-PASSession
        Write-Output 'Session closed successfully.'
    } else {
        Write-Output 'Session token was provided - NOT logging off.'
    }
} catch {
    Write-Output "`nError occurred:"
    Write-Output $_.Exception.Message

    if ($_.ErrorDetails.Message) {
        Write-Output 'API Error Details:'
        Write-Output $_.ErrorDetails.Message
    }

    # Attempt to log off even if there was an error (only if we authenticated)
    if ($shouldLogoff) {
        try {
            Close-PASSession
            Write-Output 'Session closed.'
        } catch {
            Write-Output 'Could not close session properly.'
        }
    } else {
        Write-Output 'Session token was provided - NOT logging off.'
    }

    exit 1
}
