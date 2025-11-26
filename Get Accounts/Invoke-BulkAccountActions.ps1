[CmdletBinding(DefaultParameterSetName = 'Filters')]
<#
.SYNOPSIS
	Run Account Actions on a List of Accounts using CyberArk REST API.

.DESCRIPTION
	This script executes a specified account action (Verify, Change, Reconcile) on a list of accounts filtered by Safe, PlatformID, UserName, Address, or custom keywords. Supports CyberArk PVWA v10.4 and above.

.EXAMPLE
	# Verify all accounts in a specific safe
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Verify -SafeName "MySafe"

.EXAMPLE
	# Change password for accounts filtered by PlatformID
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Change -PlatformID "WinDomain"

.EXAMPLE
	# Reconcile accounts filtered by UserName and Address
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Reconcile -UserName "svc_account" -Address "server01.example.com"

.EXAMPLE
	# Use a logon token for authentication
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Verify -SafeName "MySafe" -logonToken $token

.EXAMPLE
	# Use vault stored credentials
	$cred = Get-Credential
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Change -SafeName "MySafe" -PVWACredentials $cred

.EXAMPLE
	# Disable SSL verification (not recommended)
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Verify -DisableSSLVerify

.NOTES
	Author: Assaf Miron
	CyberArk PVWA v10.4+
	For more information, see script comments and documentation.
#>
###########################################################################
[CmdletBinding(DefaultParameterSetName = 'Filters')]
param
(
	# The URL of the CyberArk PVWA instance.
	[Parameter(Mandatory = $true, HelpMessage = 'Enter the PVWA URL')]
	#[ValidateScript({ Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30 })]
	[Alias('url')]
	[String]$PVWAURL,

	# Authentication type. Valid values: cyberark, ldap, radius. Default: cyberark.
	[Parameter(Mandatory = $false, HelpMessage = 'Enter the Authentication type (Default:CyberArk)')]
	[ValidateSet('cyberark', 'ldap', 'radius')]
	[String]$AuthType = 'cyberark',

	# Disable SSL certificate verification (not recommended).
	[Parameter(Mandatory = $false, HelpMessage = 'Disable SSL certificate verification (not recommended).')]
	[Switch]$DisableSSLVerify,

	# The account action to perform. Valid values: Verify, Change, Reconcile.
	[Parameter(Mandatory = $true, HelpMessage = 'The account action to perform. Valid values: Verify, Change, Reconcile.')]
	[ValidateSet('Verify', 'Change', 'Reconcile')]
	[Alias('Action')]
	[String]$AccountsAction = 'Verify',

	# Filter accounts by Safe name (max 28 chars).
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Enter a Safe Name to search in (max 28 chars).')]
	[ValidateScript({ $_.Length -le 28 })]
	[Alias('Safe')]
	[String]$SafeName,

	# Filter accounts by PlatformID.
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Enter a PlatformID to filter accounts by.')]
	[String]$PlatformID,

	# Filter accounts by UserName.
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Enter a UserName to filter accounts by.')]
	[String]$UserName,

	# Filter accounts by Address.
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Enter an Address to filter accounts by.')]
	[String]$Address,

	# Filter accounts by custom keywords (space-separated).
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Enter filter Keywords. List of keywords are separated with space to search in accounts.')]
	[String]$Custom,

	# Only include accounts where previous action failed.
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Only include accounts where previous action failed.')]
	[Switch]$FailedOnly,

	# Only include accounts with CPM disabled.
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Only include accounts with CPM disabled.')]
	[Switch]$CPMDisabled,

	# Provide an existing logon token for authentication.
	[Parameter(Mandatory = $false, HelpMessage = 'Provide an existing logon token for authentication.')]
	$logonToken,

	# Vault stored credentials for authentication.
	[Parameter(Mandatory = $false, HelpMessage = 'Vault Stored Credentials for authentication.')]
	[PSCredential]$PVWACredentials,

	# Disable automatic logoff at script end
	[Parameter(Mandatory = $false, HelpMessage = 'Disable automatic logoff at script end.')]
	[Switch]$DisableLogoff,

	# Include call stack information in verbose output.
	[Parameter(Mandatory = $false, DontShow, HelpMessage = 'Include Call Stack in Verbose output.')]
	[Switch]$IncludeCallStack,

	# Create a separate verbose log file.
	[Parameter(Mandatory = $false, DontShow, HelpMessage = 'Create a separate verbose log file.')]
	[Switch]$UseVerboseFile,

	# Allow sensitive data to be logged (for debugging only)
	[Parameter(Mandatory = $false, DontShow, HelpMessage = 'Allow sensitive data to be logged (debugging only).')]
	[Switch]$LogSensitiveData
)

# version 1.1

# Get Script Location
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Get Debug / Verbose parameters for Script
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$global:IncludeCallStack = $IncludeCallStack.IsPresent
$global:UseVerboseFile = $UseVerboseFile.IsPresent
$global:LogSensitiveData = $LogSensitiveData.IsPresent


# ------ SET global parameters ------
# Set Log file path
$global:LOG_FILE_PATH = "$ScriptLocation\BulkAccountActions.log"

# Set a global Header Token parameter
$global:g_LogonHeader = $null

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL + '/api'
$URL_Authentication = $URL_PVWAAPI + '/auth'
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + '/Logoff'

# URL Methods
# -----------
$URL_Accounts = $URL_PVWAAPI + '/Accounts'
$URL_AccountsDetails = $URL_PVWAAPI + '/Accounts/{0}'
$URL_AccountChange = $URL_AccountsDetails + '/Change'
$URL_AccountVerify = $URL_AccountsDetails + '/Verify'
$URL_AccountReconcile = $URL_AccountsDetails + '/Reconcile'


# Script Defaults
# ---------------

#region Writer Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
# Return Values..: None
# =================================================================================================================================
function Write-LogMessage {
	<#
.SYNOPSIS
	Method to log a message on screen and in a log file
.DESCRIPTION
	Logging The input Message to the Screen and the Log File.
	The Message Type is presented in colours on the screen based on the type
.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug, Verbose)
.PARAMETER pad
	Padding for verbose message alignment
#>
	param(
		[Parameter(Mandatory = $true)]
		[AllowEmptyString()]
		[String]$MSG,
		[Parameter(Mandatory = $false)]
		[Switch]$Header,
		[Parameter(Mandatory = $false)]
		[Switch]$SubHeader,
		[Parameter(Mandatory = $false)]
		[Switch]$Footer,
		[Parameter(Mandatory = $false)]
		[ValidateSet('Info', 'Warning', 'Error', 'Debug', 'Verbose')]
		[String]$type = 'Info',
		[Parameter(Mandatory = $false)]
		[String]$LogFile = $LOG_FILE_PATH,
		[Parameter(Mandatory = $false)]
		[int]$pad = 20
	)

	$verboseFile = $($LOG_FILE_PATH.replace('.log', '_Verbose.log'))
	try {
		if ($Header) {
			'=======================================' | Out-File -Append -FilePath $LOG_FILE_PATH
			Write-Host '======================================='
		}
		elseif ($SubHeader) {
			'------------------------------------' | Out-File -Append -FilePath $LOG_FILE_PATH
			Write-Host '------------------------------------'
		}

		$LogTime = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')]`t"
		$msgToWrite = "$LogTime"
		$writeToFile = $true
		
		# Replace empty message with 'N/A'
		if ([string]::IsNullOrEmpty($Msg)) {
			$Msg = 'N/A'
		}
		
		# Mask Passwords
		$Msg = Remove-SensitiveData -Msg $Msg
		
		# Check the message type
		switch ($type) {
			'Info' {
				Write-Host $MSG.ToString()
				$msgToWrite += "[INFO]`t`t$Msg"
			}
			'Warning' {
				Write-Host $MSG.ToString() -ForegroundColor DarkYellow
				$msgToWrite += "[WARNING]`t$Msg"
				if ($UseVerboseFile) {
					$msgToWrite | Out-File -Append -FilePath $verboseFile
				}
			}
			'Error' {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t`t$Msg"
				if ($UseVerboseFile) {
					$msgToWrite | Out-File -Append -FilePath $verboseFile
				}
			}
			'Debug' {
				if ($InDebug -or $InVerbose) {
					Write-Debug $MSG
					$writeToFile = $true
					$msgToWrite += "[DEBUG]`t`t$Msg"
				}
				else {
					$writeToFile = $False
				}
			}
			'Verbose' {
				if ($InVerbose -or $UseVerboseFile) {
					$arrMsg = $msg.split(":`t", 2)
					if ($arrMsg.Count -gt 1) {
						$msg = $arrMsg[0].PadRight($pad) + $arrMsg[1]
					}
					$msgToWrite += "[VERBOSE]`t$Msg"
					
					if ($global:IncludeCallStack) {
						$stack = Get-CallStack
						$stackMsg = "CallStack:`t$stack"
						$arrstackMsg = $stackMsg.split(":`t", 2)
						if ($arrstackMsg.Count -gt 1) {
							$stackMsg = $arrstackMsg[0].PadRight($pad) + $arrstackMsg[1].trim()
						}
						Write-Verbose $stackMsg
						$msgToWrite += "`n$LogTime"
						$msgToWrite += "[STACK]`t`t$stackMsg"
					}
					
					if ($InVerbose) {
						Write-Verbose $MSG
					} else {
						$writeToFile = $False
					}
					
					if ($UseVerboseFile) {
						$msgToWrite | Out-File -Append -FilePath $verboseFile
					}
				} else {
					$writeToFile = $False
				}
			}
		}
		
		if ($writeToFile) {
			$msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH
		}
		
		if ($Footer) {
			'=======================================' | Out-File -Append -FilePath $LOG_FILE_PATH
			Write-Host '======================================='
		}
	} catch {
		Write-Error "Error in writing log: $($_.Exception.Message)"
	}
}

function Get-CallStack {
	<#
.SYNOPSIS
	Retrieves the current PowerShell call stack for debugging
.DESCRIPTION
	Returns a formatted string of the call stack excluding internal functions
#>
	$stack = ''
	$excludeItems = @('Write-LogMessage', 'Get-CallStack', '<ScriptBlock>')
	Get-PSCallStack | ForEach-Object {
		if ($PSItem.Command -notin $excludeItems) {
			$command = $PSitem.Command
			if ($command -eq $Global:scriptName) {
				$command = 'Base'
			} elseif ([string]::IsNullOrEmpty($command)) {
				$command = '**Blank**'
			}
			$Location = $PSItem.Location
			$stack = $stack + "$command $Location; "
		}
	}
	return $stack
}

function Remove-SensitiveData {
	<#
.SYNOPSIS
	Removes sensitive data from log messages
.DESCRIPTION
	Masks passwords, tokens, and other sensitive data in log messages using regex patterns
.PARAMETER message
	The message to sanitize
#>
	[CmdletBinding()]
	param (
		[Alias('MSG', 'value', 'string')]
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$message
	)
	
	begin {
		$cleanedMessage = $message
	}
	
	process {
		if ($global:LogSensitiveData -eq $true) {
			# Allows sensitive data to be logged - useful for debugging authentication issues
			return $message
		}
		
		# List of fields that contain sensitive data to check for
		$checkFor = @('password', 'secret', 'NewCredentials', 'access_token', 'client_secret', 'auth', 'Authorization', 'Answer', 'Token')
		
		# Check for sensitive data in the message
		$checkFor | ForEach-Object {
			# Check for sensitive data escaped with quotes or double quotes
			if ($cleanedMessage -imatch "[{\\""']{2,}\s{0,}$PSitem\s{0,}[\\""']{2,}\s{0,}[:=][\\""']{2,}\s{0,}(?<Sensitive>.*?)\s{0,}[\\""']{2,}(?=[,:;])") {
				$cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
			}
			# Check for sensitive data not escaped with quotes or double quotes
			elseif ($cleanedMessage -imatch "[""']{1,}\s{0,}$PSitem\s{0,}[""']{1,}\s{0,}[:=][""']{1,}\s{0,}(?<Sensitive>.*?)\s{0,}[""']{1,}") {
				$cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
			}
			# Check for Sensitive data in pure JSON without quotes
			elseif ($cleanedMessage -imatch "(?:\s{0,}$PSitem\s{0,}[:=])\s{0,}(?<Sensitive>.*?)(?=; |:|,|}|\))") {
				$cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
			}
		}
	}
	
	end {
		return $cleanedMessage
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Collect-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
function Collect-ExceptionMessage {
	<#
.SYNOPSIS
	Formats exception messages
.DESCRIPTION
	Formats exception messages including inner exceptions
.PARAMETER e
	The Exception object to format
#>
	param(
		[Exception]$e
	)

	begin {
	}
	process {
		$msg = 'Source:{0}; Message: {1}' -f $e.Source, $e.Message
		while ($e.InnerException) {
			$e = $e.InnerException
			$msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
		}
		return $msg
	}
	end {
	}
}
#endregion

#region Helper Functions
function Test-CommandExists {
	<#
.SYNOPSIS
	Tests if a PowerShell command exists
.DESCRIPTION
	Checks if a command is available in the current PowerShell session
.PARAMETER command
	The command name to test
#>
	param (
		[Parameter(Mandatory = $true)]
		[string]$command
	)
	
	$oldPreference = $ErrorActionPreference
	$ErrorActionPreference = 'stop'
	try {
		if (Get-Command $command) {
			return $true
		}
	} catch {
		Write-Host "$command does not exist"
		return $false
	} finally {
		$ErrorActionPreference = $oldPreference
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Disable-SSLVerification
# Description....: Disables the SSL Verification (bypass self signed SSL certificates)
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
function Disable-SSLVerification {
	<#
.SYNOPSIS
	Bypass SSL certificate validations
.DESCRIPTION
	Disables the SSL Verification (bypass self signed SSL certificates)
.NOTES
	Not recommended for production use
#>
	try {
		Write-LogMessage -Type Warning -MSG "Disabling SSL verification - not recommended for production"
		
		# Using Proxy Default credentials if the Server needs Proxy credentials
		[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
		
		# Using TLS 1.2 as security protocol verification
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
		
		# Disable SSL Verification
		if (-not('DisableCertValidationCallback' -as [type])) {
			Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class DisableCertValidationCallback {
	public static bool ReturnTrue(object sender,
		X509Certificate certificate,
		X509Chain chain,
		SslPolicyErrors sslPolicyErrors) { return true; }

	public static RemoteCertificateValidationCallback GetDelegate() {
		return new RemoteCertificateValidationCallback(DisableCertValidationCallback.ReturnTrue);
	}
}
'@
		}

		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [DisableCertValidationCallback]::GetDelegate()
	} catch {
		Write-LogMessage -Type Error -MSG "Failed to disable SSL verification: $($_.Exception.Message)"
		throw
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Invoke-Rest
# Description....: Invoke REST Method
# Parameters.....: Command method, URI, Header, Body
# Return Values..: REST response
# =================================================================================================================================
function Invoke-Rest {
	<#
.SYNOPSIS
	Invoke REST Method
.DESCRIPTION
	Invoke REST Method with comprehensive error handling
.PARAMETER Command
	The REST Command method to run (GET, POST, PATCH, DELETE, PUT)
.PARAMETER URI
	The URI to use as REST API
.PARAMETER Header
	The Header as Dictionary object
.PARAMETER Body
	(Optional) The REST Body
.PARAMETER ErrAction
	(Optional) The Error Action to perform in case of error. By default "Continue"
.PARAMETER TimeoutSec
	(Optional) Timeout in seconds. Default 2700
.PARAMETER ContentType
	(Optional) Content type. Default "application/json"
#>
	param (
		[Parameter(Mandatory = $true)]
		[ValidateSet('GET', 'POST', 'DELETE', 'PATCH', 'PUT')]
		[Alias('Method')]
		[String]$Command,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String]$URI,
		[Parameter(Mandatory = $false)]
		[Alias('Headers')]
		$Header,
		[Parameter(Mandatory = $false)]
		$Body,
		[Parameter(Mandatory = $false)]
		[ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
		[String]$ErrAction = 'Continue',
		[Parameter(Mandatory = $false)]
		[int]$TimeoutSec = 2700,
		[Parameter(Mandatory = $false)]
		[string]$ContentType = 'application/json'
	)
	
	Write-LogMessage -type Verbose -MSG "Invoke-Rest: Starting $Command request to $URI"
	$restResponse = $null
	
	try {
		if ([string]::IsNullOrEmpty($Body)) {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest: Invoke-RestMethod -Uri $URI -Method $Command -ContentType $ContentType -TimeoutSec $TimeoutSec"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType $ContentType -TimeoutSec $TimeoutSec -ErrorAction $ErrAction -Verbose:$false -Debug:$false
		} else {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest: Invoke-RestMethod -Uri $URI -Method $Command -ContentType $ContentType -TimeoutSec $TimeoutSec (with body)"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType $ContentType -Body $Body -TimeoutSec $TimeoutSec -ErrorAction $ErrAction -Verbose:$false -Debug:$false
		}
		Write-LogMessage -type Verbose -MSG "Invoke-Rest: Request completed successfully"
	} catch {
		# Handle various error scenarios
		$statusCode = $null
		$errorMessage = $_.Exception.Message
		
		if ($_.Exception.Response) {
			$statusCode = $_.Exception.Response.StatusCode.value__
		}
		
		# Check if we have JSON error details
		if ($PSItem.ErrorDetails.Message) {
			try {
				$Details = ($PSItem.ErrorDetails.Message | ConvertFrom-Json)
				
				# Handle specific CyberArk error codes
				switch ($Details.ErrorCode) {
					'PASWS006E' {
						# No Session token
						Write-LogMessage -type Error -MSG "Authentication error: $($Details.ErrorMessage)"
						throw "PASWS006E: $($Details.ErrorMessage)"
					}
					'PASWS013E' {
						# Authentication failed
						Write-LogMessage -type Error -MSG "Authentication failed: $($Details.ErrorMessage)"
						throw "PASWS013E: $($Details.ErrorMessage)"
					}
					'SFWS0007' {
						# Safe has been deleted or does not exist
						Write-LogMessage -type Warning -MSG "Safe error: $($Details.ErrorMessage)"
						throw $_.Exception
					}
					'SFWS0002' {
						# Safe has already been defined
						Write-LogMessage -type Warning -MSG "$($Details.ErrorMessage)"
						throw "$($Details.ErrorMessage)"
					}
					'SFWS0012' {
						# Already a member
						Write-LogMessage -type Verbose -MSG "Invoke-Rest: $($Details.ErrorMessage)"
						throw $PSItem
					}
					default {
						Write-LogMessage -type Error -MSG "API Error Code: $($Details.ErrorCode)"
						Write-LogMessage -type Error -MSG "API Error Message: $($Details.ErrorMessage)"
						throw $(New-Object System.Exception ("Invoke-Rest: $($Details.ErrorMessage)", $_.Exception))
					}
				}
			} catch {
				# If JSON parsing fails or other error, continue to general error handling
			}
		}
		
		# Handle HTTP status code errors
		if ($statusCode) {
			switch ($statusCode) {
				401 {
					Write-LogMessage -type Error -MSG "Received error 401 - Unauthorized access"
					throw "HTTP 401: Unauthorized - Check credentials and permissions"
				}
				403 {
					Write-LogMessage -type Error -MSG "Received error 403 - Forbidden access"
					throw "HTTP 403: Forbidden - Insufficient permissions"
				}
				404 {
					Write-LogMessage -type Warning -MSG "Received error 404 - Resource not found"
					throw "HTTP 404: Resource not found at $URI"
				}
				default {
					Write-LogMessage -type Error -MSG "HTTP Status Code: $statusCode"
					Write-LogMessage -type Error -MSG "Status Description: $($_.Exception.Response.StatusDescription)"
				}
			}
		}
		
		# Handle network errors
		if ($errorMessage -match 'The remote name could not be resolved') {
			Write-LogMessage -type Error -MSG "Network error - The remote name could not be resolved: $PVWAURL"
			throw "Network Error: Cannot resolve $PVWAURL - Check URL and network connectivity"
		}
		
		# Generic error handling
		Write-LogMessage -type Verbose -MSG "Invoke-Rest: Error in running $Command on '$URI'"
		Write-LogMessage -type Verbose -MSG "Invoke-Rest: Error Message: $errorMessage"
		Write-LogMessage -type Verbose -MSG "Invoke-Rest: Exception: $($_.Exception.Message)"
		
		throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
	}
	
	Write-LogMessage -type Verbose -MSG "Invoke-Rest: Completed"
	return $restResponse
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LogonHeader
# Description....: Creates a logon header for API authentication
# Parameters.....: Credentials
# Return Values..: Logon Header
# =================================================================================================================================
function Get-LogonHeader {
	<#
.SYNOPSIS
	Get-LogonHeader
.DESCRIPTION
	Creates or retrieves the logon header for API authentication
.PARAMETER Credentials
	The REST API Credentials to authenticate
#>
	param(
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credentials
	)

	if ([string]::IsNullOrEmpty($g_LogonHeader)) {
		Write-LogMessage -Type Verbose -MSG "Get-LogonHeader: Creating new logon session"
		
		# Disable SSL Verification to contact PVWA if requested
		if ($DisableSSLVerify) {
			Disable-SSLVerification
		} else {
			# Set TLS 1.2 for secure connections
			try {
				[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
			} catch {
				Write-LogMessage -Type Warning -MSG "Could not set TLS 1.2"
			}
		}

		# Create the POST Body for the Logon
		$logonBody = @{
			username          = $Credentials.username.Replace('\', '')
			password          = $Credentials.GetNetworkCredential().password
			concurrentSession = $true
		} | ConvertTo-Json
		
		try {
			# Logon
			Write-LogMessage -Type Verbose -MSG "Get-LogonHeader: Attempting logon to $URL_Logon"
			$logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody

			# Clear logon body
			$logonBody = ''
		} catch {
			throw $(New-Object System.Exception ("Get-LogonHeader: Logon failed - $($_.Exception.Message)", $_.Exception))
		}

		if ([string]::IsNullOrEmpty($logonToken)) {
			throw 'Get-LogonHeader: Logon Token is Empty - Cannot login'
		}

		# Create a Logon Token Header
		Write-LogMessage -Type Verbose -MSG "Get-LogonHeader: Creating authorization header"
		$logonHeader = New-Object 'System.Collections.Generic.Dictionary[[String],[String]]'
		$logonHeader.Add('Authorization', $logonToken)

		Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global
		Write-LogMessage -Type Info -MSG "Successfully authenticated to PVWA"
	} else {
		Write-LogMessage -Type Verbose -MSG "Get-LogonHeader: Using existing logon session"
	}

	return $g_LogonHeader
}

function Invoke-Logoff {
	<#
.SYNOPSIS
	Invoke-Logoff
.DESCRIPTION
	Logoff a PVWA session
#>
	try {
		# Logoff the session
		if ($null -ne $g_LogonHeader) {
			Write-LogMessage -type Info -MSG 'Logging off PVWA session...'
			Invoke-Rest -Method Post -Uri $URL_Logoff -Headers $g_LogonHeader -ContentType 'application/json' -TimeoutSec 30 | Out-Null
			Set-Variable -Name g_LogonHeader -Value $null -Scope global
			Write-LogMessage -type Verbose -MSG 'Session logged off successfully'
		}
	} catch {
		Write-LogMessage -Type Warning -MSG "Logoff failed (non-critical): $($_.Exception.Message)"
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Format-URL
# Description....: Encodes a text for URL
# Parameters.....: Text
# Return Values..: Encoded Text
# =================================================================================================================================
function Format-URL {
	<#
.SYNOPSIS
	Format-URL
.DESCRIPTION
	Encodes a text for URL usage
.PARAMETER sText
	The text to encode
#>
	param(
		[Parameter(Mandatory = $true)]
		[string]$sText
	)
	
	if ($sText.Trim() -ne '') {
		Write-LogMessage -Type Verbose -Msg "Format-URL: Encoding '$sText'"
		return [URI]::EscapeDataString($sText)
	} else {
		return ''
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-SearchCriteria
# Description....: Creates a search criteria URL for PVWA
# Parameters.....: Base URL, Search keywords, safe name
# Return Values..: Formatted URL with search criteria
# =================================================================================================================================
function Get-SearchCriteria {
	<#
.SYNOPSIS
	Get-SearchCriteria
.DESCRIPTION
	Creates a search criteria URL for PVWA account filtering
.PARAMETER sURL
	The base URL
.PARAMETER sSearch
	Search keywords
.PARAMETER sSafeName
	Safe name to filter by
#>
	param (
		[Parameter(Mandatory = $true)]
		[string]$sURL,
		[Parameter(Mandatory = $false)]
		[string]$sSearch,
		[Parameter(Mandatory = $false)]
		[string]$sSafeName
	)
	
	[string]$retURL = $sURL
	$retURL += '?'

	if ($sSearch.Trim() -ne '') {
		Write-LogMessage -Type Verbose -Msg "Get-SearchCriteria: Adding search term '$sSearch'"
		$retURL += "search=$(Format-URL $sSearch)&"
	}
	
	if ($sSafeName.Trim() -ne '') {
		Write-LogMessage -Type Verbose -Msg "Get-SearchCriteria: Adding safe filter '$sSafeName'"
		$retURL += "filter=safename eq $(Format-URL $sSafeName)&"
	}

	if ($retURL[-1] -eq '&') {
		$retURL = $retURL.substring(0, $retURL.length - 1)
	}
	
	Write-LogMessage -Type Verbose -Msg "Get-SearchCriteria: Final URL: $retURL"
	return $retURL
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-FilteredAccounts
# Description....: Returns a list of Accounts according to a filter
# Parameters.....: Safe name, Platform ID, Custom keywords, User name, address
# Return Values..: List of Filtered Accounts
# =================================================================================================================================
function Get-FilteredAccounts {
	<#
.SYNOPSIS
	Get-FilteredAccounts
.DESCRIPTION
	Returns a list of Accounts according to specified filters
.PARAMETER sSafeName
	Safe name to filter by
.PARAMETER sPlatformID
	Platform ID to filter by
.PARAMETER sUserName
	Username to filter by
.PARAMETER sAddress
	Address to filter by
.PARAMETER sCustomKeywords
	Custom keywords to search for
.PARAMETER bFailedOnly
	Only return accounts with failed CPM operations
#>
	param (
		[Parameter(Mandatory = $false)]
		[string]$sSafeName,
		[Parameter(Mandatory = $false)]
		[string]$sPlatformID,
		[Parameter(Mandatory = $false)]
		[string]$sUserName,
		[Parameter(Mandatory = $false)]
		[string]$sAddress,
		[Parameter(Mandatory = $false)]
		[string]$sCustomKeywords,
		[Parameter(Mandatory = $false)]
		[bool]$bFailedOnly,
		[Parameter(Mandatory = $false)]
		[bool]$bCPMDisabled
	)

	$GetAccountsList = @()
	$FilteredAccountsList = @()
	
	try {
		Write-LogMessage -Type Info -MSG "Searching for accounts with filters..."
		if (-not [string]::IsNullOrEmpty($sSafeName)) {
			Write-LogMessage -Type Info -MSG "  Safe Name: $sSafeName"
		}
		if (-not [string]::IsNullOrEmpty($sPlatformID)) {
			Write-LogMessage -Type Info -MSG "  Platform ID: $sPlatformID"
		}
		if (-not [string]::IsNullOrEmpty($sUserName)) {
			Write-LogMessage -Type Info -MSG "  Username: $sUserName"
		}
		if (-not [string]::IsNullOrEmpty($sAddress)) {
			Write-LogMessage -Type Info -MSG "  Address: $sAddress"
		}
		if ($bFailedOnly) {
			Write-LogMessage -Type Info -MSG "  Failed Only: True"
		}
		if ($bCPMDisabled) {
			Write-LogMessage -Type Info -MSG "  CPM Disabled: True"
		}
		
		$AccountsURLWithFilters = ''
		$Keywords = "$sPlatformID $sUserName $sAddress $sCustomKeywords"
		$AccountsURLWithFilters = "$(Get-SearchCriteria -sURL $URL_Accounts -sSearch $Keywords -sSafeName $sSafeName)&limit=500"
		Write-LogMessage -Type Verbose -MSG "Get-FilteredAccounts: Using URL: $AccountsURLWithFilters"
	} catch {
		throw $(New-Object System.Exception ('Get-FilteredAccounts: Error creating filtered URL', $_.Exception))
	}
	
	try {
		# Get all Accounts with pagination
		Write-LogMessage -Type Verbose -MSG "Get-FilteredAccounts: Retrieving accounts from API"
		$GetAccountsResponse = Invoke-Rest -Command Get -Uri $AccountsURLWithFilters -Header $Global:g_LogonHeader

		$GetAccountsList += $GetAccountsResponse.value
		Write-LogMessage -Type Info -MSG "Found $($GetAccountsList.count) accounts..."
		
		$nextLink = $GetAccountsResponse.nextLink
		Write-LogMessage -Type Verbose -MSG "Get-FilteredAccounts: Next link: $nextLink"

		# Handle pagination
		while (-not [string]::IsNullOrEmpty($nextLink)) {
			Write-LogMessage -Type Verbose -MSG "Get-FilteredAccounts: Retrieving next page"
			$GetAccountsResponse = Invoke-Rest -Command Get -Uri $("$PVWAURL/$nextLink") -Header $Global:g_LogonHeader
			$nextLink = $GetAccountsResponse.nextLink
			Write-LogMessage -Type Verbose -MSG "Get-FilteredAccounts: Next link: $nextLink"
			$GetAccountsList += $GetAccountsResponse.value
			Write-LogMessage -Type Info -MSG "Found $($GetAccountsList.count) accounts so far..."
		}

		Write-LogMessage -Type Info -MSG "Retrieved total of $($GetAccountsList.count) accounts from API"
		
		# Create a dynamic filter array
		$WhereArray = @()
		if (-not [string]::IsNullOrEmpty($sUserName)) {
			$WhereArray += '$_.userName -eq $sUserName'
		}
		if (-not [string]::IsNullOrEmpty($sAddress)) {
			$WhereArray += '$_.address -eq $sAddress'
		}
		if (-not [string]::IsNullOrEmpty($sPlatformID)) {
			$WhereArray += '$_.platformId -eq $sPlatformID'
		}
		if ($bFailedOnly -and $bCPMDisabled) {
			$WhereArray += '($_.secretManagement.status -eq "failure" -or $_.secretManagement.status -eq "failed" -or $_.secretManagement.manualManagementReason -like "*CPM*")'
		} elseif ($bFailedOnly) {
			$WhereArray += '($_.secretManagement.status -eq "failure" -or $_.secretManagement.status -eq "failed")'
		} elseif ($bCPMDisabled) {
			$WhereArray += '$_.secretManagement.manualManagementReason -like "*CPM*"'
		}

		# Filter Accounts based on input properties
		if ($WhereArray.Count -gt 0) {
			Write-LogMessage -Type Verbose -MSG "Get-FilteredAccounts: Applying additional filters"
			$WhereFilter = [scriptblock]::Create(($WhereArray -join ' -and '))
			$FilteredAccountsList = ($GetAccountsList | Where-Object $WhereFilter)
			Write-LogMessage -Type Info -MSG "After filtering: $($FilteredAccountsList.count) accounts match criteria"
		} endedlse {
			$FilteredAccountsList = $GetAccountsList
		}
	} catch {
		throw $(New-Object System.Exception ('Get-FilteredAccounts: Error retrieving accounts from API', $_.Exception))
	}

	return $FilteredAccountsList
}
#endregion

#region Main Script Execution
# =================================================================================================================================
# Main Script Logic
# =================================================================================================================================

Write-LogMessage -Type Info -MSG 'Starting Bulk Account Actions script' -Header -LogFile $LOG_FILE_PATH
Write-LogMessage -Type Info -MSG "Script Version: 1.2 (Corrected)"
Write-LogMessage -Type Info -MSG "PowerShell Version: $($PSVersionTable.PSVersion.ToString())"
Write-LogMessage -Type Info -MSG "CyberArk PVWA URL: $PVWAURL"
Write-LogMessage -Type Info -MSG "Authentication Type: $AuthType"
Write-LogMessage -Type Info -MSG "Account Action: $AccountsAction"

if ($InDebug) {
	Write-LogMessage -Type Info -MSG 'Running in Debug Mode' -LogFile $LOG_FILE_PATH
}
if ($InVerbose) {
	Write-LogMessage -Type Info -MSG 'Running in Verbose Mode' -LogFile $LOG_FILE_PATH
}

# Check PowerShell version
if (-not (Test-CommandExists Invoke-RestMethod)) {
	Write-LogMessage -Type Error -MSG "This script requires PowerShell version 3 or above"
	Write-LogMessage -Type Error -MSG "Current version: $($PSVersionTable.PSVersion.ToString())"
	return
}

# Check that the PVWA URL is OK
if ($PVWAURL -ne '') {
	if ($PVWAURL.Substring($PVWAURL.Length - 1) -eq '/') {
		$PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
		Write-LogMessage -Type Verbose -MSG "Removed trailing slash from PVWA URL"
	}
	
	# Validate URL format
	if ($PVWAURL -notmatch '^https?://') {
		Write-LogMessage -Type Error -MSG "PVWA URL must start with http:// or https://"
		return
	}
} else {
	Write-LogMessage -Type Error -MSG 'PVWA URL cannot be empty'
	return
}

# Get Credentials to Login
$caption = 'Bulk Account Actions'
$msg = "Enter your PAS User name and Password ($AuthType)"

try {
	# Check if logon token was provided
	if (![string]::IsNullOrEmpty($logonToken)) {
		Write-LogMessage -Type Info -MSG "Using provided logon token"
		if ($logonToken.GetType().name -eq 'String') {
			$logonHeader = @{Authorization = $logonToken }
			Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global
		} else {
			Set-Variable -Name g_LogonHeader -Value $logonToken -Scope global
		}
	}
	# Check if credentials were provided
	elseif (![string]::IsNullOrEmpty($PVWACredentials)) {
		Write-LogMessage -Type Info -MSG "Using provided credentials"
		Get-LogonHeader -Credentials $PVWACredentials
	}
	# Prompt for credentials
	else {
		Write-LogMessage -Type Info -MSG "Prompting for credentials"
		$creds = $Host.UI.PromptForCredential($caption, $msg, '', '')
		
		if ($null -eq $creds) {
			Write-LogMessage -Type Error -MSG "No credentials provided - exiting"
			return
		}
		
		Get-LogonHeader -Credentials $creds
	}
} catch {
	Write-LogMessage -type Error -MSG "Error during authentication: $(Collect-ExceptionMessage $_.Exception)"
	return
}

# Verify we have a valid logon header
if ($null -eq $g_LogonHeader) {
	Write-LogMessage -Type Error -MSG "Failed to create logon header - cannot proceed"
	return
}

# Main processing
try {
	Write-LogMessage -Type Info -MSG "Beginning bulk account action: $AccountsAction" -SubHeader
	
	# Determine the action URL
	$accountAction = ''
	switch ($AccountsAction) {
		'Verify' {
			Write-LogMessage -Type Info -MSG 'Action: Verify password for all filtered accounts'
			$accountAction = $URL_AccountVerify
		}
		'Change' {
			Write-LogMessage -Type Info -MSG 'Action: Change password for all filtered accounts'
			$accountAction = $URL_AccountChange
		}
		'Reconcile' {
			Write-LogMessage -Type Info -MSG 'Action: Reconcile password for all filtered accounts'
			$accountAction = $URL_AccountReconcile
		}
	}
	
	# Get all Relevant Accounts
	Write-LogMessage -Type Info -MSG "Retrieving filtered accounts..." -SubHeader
	$filteredAccounts = Get-FilteredAccounts -sSafeName $SafeName -sPlatformID $PlatformID -sUserName $UserName -sAddress $Address -sCustomKeywords $Custom -bFailedOnly $FailedOnly.IsPresent -bCPMDisabled $CPMDisabled.IsPresent
	
	if ($null -eq $filteredAccounts -or $filteredAccounts.Count -eq 0) {
		Write-LogMessage -Type Warning -MSG "No accounts found matching the specified criteria"
		Write-LogMessage -Type Info -MSG "Please verify your filter parameters and try again"
	} else {
		Write-LogMessage -Type Info -MSG "Processing $($filteredAccounts.Count) accounts" -SubHeader
		
		# Statistics tracking
		$successCount = 0
		$failCount = 0
		$currentCount = 0
		
		# Run Account Action on relevant Accounts
		foreach ($account in $filteredAccounts) {
			$currentCount++
			$accountName = $account.Name
			$accountSafe = $account.safeName
			$accountId = $account.id
			
			Write-LogMessage -Type Info -MSG "[$currentCount/$($filteredAccounts.Count)] Processing account: '$accountName' (Safe: '$accountSafe')"
			Write-LogMessage -Type Verbose -MSG "Account ID: $accountId"
			
			try {
				$actionURL = $accountAction -f $accountId
				Write-LogMessage -Type Verbose -MSG "Submitting $AccountsAction request to: $actionURL"
				
				$null = Invoke-Rest -Uri $actionURL -Command POST -Body '' -Header $global:g_LogonHeader
				
				Write-LogMessage -Type Info -MSG "  [SUCCESS] $AccountsAction submitted for account '$accountName'"
				$successCount++
			} catch {
				Write-LogMessage -Type Error -MSG "  [FAILED] Error submitting $AccountsAction for account '$accountName'"
				Write-LogMessage -Type Error -MSG "  Error: $($_.Exception.Message)"
				$failCount++
			}
		}
		
		# Display summary
		Write-LogMessage -Type Info -MSG "Bulk action completed" -SubHeader
		Write-LogMessage -Type Info -MSG "Total accounts processed: $($filteredAccounts.Count)"
		Write-LogMessage -Type Info -MSG "Successful submissions: $successCount"
		Write-LogMessage -Type Info -MSG "Failed submissions: $failCount"
		
		if ($failCount -gt 0) {
			Write-LogMessage -Type Warning -MSG "Some accounts failed to process - review log for details"
		}
	}
} catch {
	Write-LogMessage -Type Error -MSG "Critical error during bulk account actions: $(Collect-ExceptionMessage $_.Exception)"
}

# Logoff the session
Write-LogMessage -Type Info -MSG "Cleaning up session..." -SubHeader
if (![string]::IsNullOrEmpty($logonToken)) {
	Write-LogMessage -Type Info -MSG 'Logon token was provided - session NOT logged off'
} elseif ($DisableLogoff) {
	Write-LogMessage -Type Info -MSG 'Logoff disabled - session NOT logged off'
} else {
	Invoke-Logoff
}

Write-LogMessage -type Info -MSG 'Bulk Account Actions script completed' -Footer -LogFile $LOG_FILE_PATH
#endregion