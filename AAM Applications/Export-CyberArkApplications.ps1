<#
.SYNOPSIS
    Exports CyberArk Applications and their authentication methods to CSV

.DESCRIPTION
    This script exports CyberArk Applications including all their authentication methods to a CSV file.
    Supports exporting all applications or filtering by specific AppID.
    Works with both Privilege Cloud and Self-Hosted PAM.

.PARAMETER PVWAUrl
    The base URL of the PVWA (e.g. https://pvwa.company.com or https://tenant.privilegecloud.cyberark.cloud)

.PARAMETER AppID
    Optional. Filter export to a specific application ID

.PARAMETER CSVPath
    Path where the CSV file will be saved

.PARAMETER Credential
    PSCredential object for authentication. If not provided, prompts for credentials

.PARAMETER AuthenticationType
    Authentication type: cyberark, ldap, or radius (default: cyberark)

.PARAMETER OTP
    One-time password for RADIUS authentication

.PARAMETER LogonToken
    Pre-existing session token. If provided, script will NOT log off at the end
    Aliases: session, sessionToken

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation (not recommended for production)

.EXAMPLE
    .\Export-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" -CSVPath ".\applications.csv"
    Exports all applications to CSV

.EXAMPLE
    .\Export-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp" -CSVPath ".\myapp.csv"
    Exports a specific application

.EXAMPLE
    .\Export-CyberArkApplications.ps1 -PVWAUrl "https://tenant.privilegecloud.cyberark.cloud" -LogonToken $token -CSVPath ".\apps.csv"
    Exports using existing session token

.NOTES
    PowerShell 5.1 compatible
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "PVWA URL (e.g. https://pvwa.company.com)")]
    [Alias("url")]
    [ValidateNotNullOrEmpty()]
    [string]$PVWAUrl,

    [Parameter(Mandatory = $false, HelpMessage = "Filter by specific Application ID")]
    [Alias("id")]
    [string]$AppID,

    [Parameter(Mandatory = $true, HelpMessage = "Path to save the CSV export file")]
    [Alias("path")]
    [ValidateNotNullOrEmpty()]
    [string]$CSVPath,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [ValidateSet("cyberark", "ldap", "radius")]
    [string]$AuthenticationType = "cyberark",

    [Parameter(Mandatory = $false)]
    [string]$OTP,

    [Parameter(Mandatory = $false)]
    [Alias("session", "sessionToken")]
    [string]$LogonToken,

    [Parameter(Mandatory = $false)]
    [switch]$DisableCertificateValidation
)

#region Helper Functions
function Write-LogMessage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Type = "INFO"
    )

    # Simple output suitable for script logs and schedulers
    Write-Output ("{0} {1}" -f $Type.PadRight(5), $Message)
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

function Convert-SecureStringToPlainText {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecureString
    )

    # Convert SecureString for API authentication
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

function Convert-ObjectToString {
    param(
        [Parameter(Mandatory = $false)]
        [psobject]$Object
    )

    # Flatten an authentication object into a single string for CSV export
    $retString = [string]::Empty

    if ($null -ne $Object) {
        $arrItems = @()

        $Object.PSObject.Properties | ForEach-Object {
            if ($_.Name -in @('authID', 'authenticationID', 'AppID')) {
                return
            }

            if ($null -eq $_.Value) {
                return
            }

            $value = $_.Value

            if ($value -is [array]) {
                # Trim array elements and join without spaces
                $value = ($value | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' }) -join ','
            } else {
                # Trim and remove spaces after commas for consistency
                $value = ([string]$value).Trim() -replace ',\s+', ','
            }

            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $arrItems += ("{0}={1}" -f $_.Name, $value)
            }
        }

        $retString = $arrItems -join ';'
    }

    return $retString
}

function Initialize-SSL {
    # Optional certificate trust bypass for test environments only
    if ($DisableCertificateValidation) {
        Write-LogMessage -Type WARN -Message "SSL certificate validation is disabled. Use only for testing."

        if (-not ([System.Management.Automation.PSTypeName]"TrustAllCertsPolicy").Type) {
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
    if (([System.Net.ServicePointManager]::SecurityProtocol -band [System.Net.SecurityProtocolType]::Tls12) -eq 0) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    }
}

function Invoke-PASRestMethod {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST", "DELETE", "PATCH")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$URI,

        [Parameter(Mandatory = $true)]
        [hashtable]$Header,

        [Parameter(Mandatory = $false)]
        [string]$Body
    )

    # Wrapper for consistent REST behaviour and error handling
    try {
        $params = @{
            Uri         = $URI
            Method      = $Method
            Headers     = $Header
            ContentType = "application/json"
            TimeoutSec  = 2700
            ErrorAction = "Stop"
        }

        if (-not [string]::IsNullOrWhiteSpace($Body)) {
            $params.Body = $Body
        }

        return Invoke-RestMethod @params
    } catch {
        Write-LogMessage -Type ERROR -Message ("REST API call failed: {0}" -f $_.Exception.Message)

        if ($_.Exception.Response) {
            try {
                Write-LogMessage -Type ERROR -Message ("Status Code: {0}" -f $_.Exception.Response.StatusCode.value__)
                Write-LogMessage -Type ERROR -Message ("Status Description: {0}" -f $_.Exception.Response.StatusDescription)
            } catch {
                Write-LogMessage -Type ERROR -Message "Could not extract HTTP status details."
            }
        }

        throw
    }
}

function Get-PASLogonHeader {
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string]$BaseURL,

        [Parameter(Mandatory = $true)]
        [string]$AuthType,

        [Parameter(Mandatory = $false)]
        [string]$OTP
    )

    # Authenticate and return standard Authorization header
    $logonURL = "{0}/API/Auth/{1}/Logon" -f $BaseURL, $AuthType
    $plainPassword = $null

    try {
        $plainPassword = Convert-SecureStringToPlainText -SecureString $Credential.Password

        if ([string]::IsNullOrWhiteSpace($plainPassword)) {
            throw "Authentication failed - empty password"
        }

        if ($AuthType -eq "radius") {
            $plainPassword = "{0},{1}" -f $plainPassword, $OTP.Trim()
        }

        # Do not log this body because it contains sensitive data
        $logonBody = @{
            username = $Credential.UserName
            password = $plainPassword
        } | ConvertTo-Json

        $response = Invoke-RestMethod -Uri $logonURL -Method Post -Body $logonBody -ContentType "application/json" -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace([string]$response)) {
            throw "Authentication failed - no token received"
        }

        return @{ Authorization = [string]$response }
    } catch {
        throw "Authentication failed: $($_.Exception.Message)"
    } finally {
        $plainPassword = $null
    }
}

function Invoke-PASLogoff {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Header,

        [Parameter(Mandatory = $true)]
        [string]$BaseURL
    )

    # Log off only when this script created the session
    try {
        $logoffURL = "{0}/API/Auth/Logoff" -f $BaseURL
        Invoke-RestMethod -Uri $logoffURL -Method Post -Headers $Header -ContentType "application/json" -ErrorAction Stop | Out-Null
    } catch {
        Write-LogMessage -Type WARN -Message ("Logoff failed: {0}" -f $_.Exception.Message)
    }
}
#endregion

#region Main Script
$managedSession = $false
$sessionHeader = $null
$exitCode = 0

try {
    Write-LogMessage -Type INFO -Message "Export CyberArk Applications - Starting"

    # Normalize URL once at the start
    $PVWAUrl = $PVWAUrl.Trim().TrimEnd('/')

    # Basic validation
    if ([string]::IsNullOrWhiteSpace($PVWAUrl)) {
        Write-LogMessage -Type ERROR -Message "PVWAUrl cannot be blank."
        exit 1
    }

    if ([string]::IsNullOrWhiteSpace($CSVPath)) {
        Write-LogMessage -Type ERROR -Message "CSVPath cannot be blank."
        exit 1
    }

    if ($AuthenticationType -eq "radius" -and [string]::IsNullOrWhiteSpace($OTP)) {
        Write-LogMessage -Type ERROR -Message "OTP is required when AuthenticationType is radius."
        exit 1
    }

    # Initialize SSL/TLS settings
    Initialize-SSL

    # Check CSV target path
    if (Test-Path -LiteralPath $CSVPath) {
        $response = Read-Host "CSV file already exists at '$CSVPath'. Overwrite? (Y/N)"
        if ($response -notmatch '^(?i)y(es)?$') {
            Write-LogMessage -Type WARN -Message "Export cancelled by user."
            exit 1
        }

        Remove-Item -LiteralPath $CSVPath -Force
    }

    # Determine whether this script owns the session
    if (-not [string]::IsNullOrWhiteSpace($LogonToken)) {
        Write-LogMessage -Type INFO -Message "Using provided session token. Script will not log off."
        $sessionHeader = @{ Authorization = $LogonToken.Trim() }
    } else {
        $managedSession = $true

        if ($null -eq $Credential) {
            $Credential = Get-Credential -Message ("Enter CyberArk credentials ({0})" -f $AuthenticationType)
        }

        if ($null -eq $Credential) {
            throw "Credentials are required to proceed."
        }

        $sessionHeader = Get-PASLogonHeader -Credential $Credential -BaseURL $PVWAUrl -AuthType $AuthenticationType -OTP $OTP
        Write-LogMessage -Type INFO -Message "Authentication successful."
    }

    # Gen1 applications endpoint
    $applicationsURL = "{0}/WebServices/PIMServices.svc/Applications" -f $PVWAUrl

    # Retrieve applications
    Write-LogMessage -Type INFO -Message "Retrieving applications..."
    $applications = @()

    if (-not [string]::IsNullOrWhiteSpace($AppID)) {
        Write-LogMessage -Type INFO -Message ("Filtering by AppID: {0}" -f $AppID)

        $encodedAppID = ConvertTo-URL -Text $AppID
        $response = Invoke-PASRestMethod -Method GET -URI ("{0}/{1}" -f $applicationsURL, $encodedAppID) -Header $sessionHeader

        # Single app response may come back in .application
        if ($null -ne $response.application) {
            $applications = @($response.application)
        } elseif ($null -ne $response.AppID) {
            $applications = @($response)
        }
    } else {
        $response = Invoke-PASRestMethod -Method GET -URI $applicationsURL -Header $sessionHeader

        if ($null -ne $response.application) {
            $applications = @($response.application)
        }
    }

    if ($applications.Count -eq 0) {
        Write-LogMessage -Type WARN -Message "No applications found."
        exit 0
    }

    Write-LogMessage -Type INFO -Message ("Found {0} application(s)." -f $applications.Count)

    # Build export rows
    $exportData = @()

    foreach ($app in $applications) {
        Write-LogMessage -Type INFO -Message ("Processing application: {0}" -f $app.AppID)

        # Base application properties for export
        $exportObject = [PSCustomObject]@{
            AppID               = $app.AppID
            Description         = $app.Description
            Location            = $app.Location
            AccessPermittedFrom = $app.AccessPermittedFrom
            AccessPermittedTo   = $app.AccessPermittedTo
            ExpirationDate      = $app.ExpirationDate
            Disabled            = $app.Disabled
            BusinessOwnerFName  = $app.BusinessOwnerFName
            BusinessOwnerLName  = $app.BusinessOwnerLName
            BusinessOwnerEmail  = $app.BusinessOwnerEmail
            BusinessOwnerPhone  = $app.BusinessOwnerPhone
            Authentications     = ""
        }

        # Retrieve auth methods for the application
        try {
            $encodedAppID = ConvertTo-URL -Text $app.AppID
            $authURL = "{0}/{1}/Authentications" -f $applicationsURL, $encodedAppID
            $authResponse = Invoke-PASRestMethod -Method GET -URI $authURL -Header $sessionHeader

            if ($null -ne $authResponse.authentication) {
                $authStrings = @()

                foreach ($auth in $authResponse.authentication) {
                    $authStrings += Convert-ObjectToString -Object $auth
                }

                $exportObject.Authentications = $authStrings -join "|"
                Write-LogMessage -Type INFO -Message ("Found {0} authentication method(s) for {1}." -f $authResponse.authentication.Count, $app.AppID)
            } else {
                Write-LogMessage -Type INFO -Message ("No authentication methods found for {0}." -f $app.AppID)
            }
        } catch {
            Write-LogMessage -Type WARN -Message ("Failed to retrieve authentication methods for {0}: {1}" -f $app.AppID, $_.Exception.Message)
        }

        $exportData += $exportObject
    }

    # Ensure target directory exists if specified
    $csvParent = Split-Path -Path $CSVPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($csvParent) -and -not (Test-Path -LiteralPath $csvParent)) {
        New-Item -Path $csvParent -ItemType Directory -Force | Out-Null
    }

    # Export to CSV
    Write-LogMessage -Type INFO -Message ("Exporting to CSV: {0}" -f $CSVPath)
    $exportData | Export-Csv -Path $CSVPath -NoTypeInformation -Encoding UTF8

    Write-LogMessage -Type INFO -Message ("Successfully exported {0} application(s)." -f $exportData.Count)
}
catch {
    $exitCode = 1
    Write-LogMessage -Type ERROR -Message ("Export failed: {0}" -f $_.Exception.Message)
}
finally {
    # Log off only when this script created the session
    if ($managedSession -and $null -ne $sessionHeader) {
        Invoke-PASLogoff -Header $sessionHeader -BaseURL $PVWAUrl
        Write-LogMessage -Type INFO -Message "Session closed."
    } elseif (-not [string]::IsNullOrWhiteSpace($LogonToken)) {
        Write-LogMessage -Type INFO -Message "Session token was provided. Not logging off."
    }

    # Clear sensitive references
    $Credential = $null
    $sessionHeader = $null

    Write-LogMessage -Type INFO -Message "Export CyberArk Applications - Complete"
    exit $exitCode
}
#endregion
