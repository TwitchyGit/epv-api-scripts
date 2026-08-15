<# ###########################################################################

NAME: Export / Import Platform

AUTHOR:  Assaf Miron, Brian Bors

COMMENT: 
This script will Export or Import a platform using REST API

SUPPORTED VERSIONS:
CyberArk PVWA v10.4 and above

VERSION HISTORY:
1.0 05/07/2018 - Initial release
1.1 08/12/2018 - Added ability to do bulk export/import
1.2 15/08/2026 - Windows PowerShell 5.1 compatibility plus interactive mode and reliability fixes

########################################################################### #>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param
(
	[Parameter(ParameterSetName = 'Interactive', Mandatory = $false)]
	[Parameter(ParameterSetName = 'Import', Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	[Parameter(ParameterSetName = 'Export', Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	[Parameter(ParameterSetName = 'ImportFile', Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	[Parameter(ParameterSetName = 'ExportFile', Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	[Parameter(ParameterSetName = 'ExportActive', Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	[Parameter(ParameterSetName = 'ExportAll', Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,

	[Parameter(Mandatory = $false, HelpMessage = "Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark", "ldap", "radius")]
	[String]$AuthType = "cyberark",	
	
	# Use this switch to Import a Platform
	[Parameter(ParameterSetName = 'Import', Mandatory = $true)][switch]$Import,
	# Use this switch to Export a Platform
	[Parameter(ParameterSetName = 'Export', Mandatory = $true)][switch]$Export,

	# Use this switch to Import a Platform using a file
	[Parameter(ParameterSetName = 'ImportFile', Mandatory = $true)][switch]$ImportFile,
	# Use this switch to Export a Platform using a file
	[Parameter(ParameterSetName = 'ExportFile', Mandatory = $true)][switch]$ExportFile,

	[Parameter(ParameterSetName = 'ExportActive', Mandatory = $true)][switch]$ExportActive,
	[Parameter(ParameterSetName = 'ExportAll', Mandatory = $true)][switch]$ExportAll,
	[Parameter(ParameterSetName = 'Interactive', Mandatory = $false)][switch]$Interactive,
	
	[Parameter(ParameterSetName = 'Export', Mandatory = $true, HelpMessage = "Enter the platform ID to export")]
	[Alias("id")]
	[string]$PlatformID,
	
	[Parameter(ParameterSetName = 'Import', Mandatory = $true, HelpMessage = "Enter the platform Zip path for import")]
	[Parameter(ParameterSetName = 'Export', Mandatory = $true, HelpMessage = "Enter the platform Zip path to export")]
	[Parameter(ParameterSetName = 'ImportFile', Mandatory = $false, HelpMessage = "Enter the platform Zip path for import")]
	[Parameter(ParameterSetName = 'ExportFile', Mandatory = $true, HelpMessage = "Enter the platform Zip path to export")]
	[Parameter(ParameterSetName = 'ExportActive', Mandatory = $true, HelpMessage = "Enter the platform Zip path to export")]
	[Parameter(ParameterSetName = 'ExportAll', Mandatory = $true, HelpMessage = "Enter the platform Zip path to export")]
	[string]$PlatformZipPath,

	# Use this to specify where file to read is
	[Parameter(ParameterSetName = 'ImportFile', Mandatory = $true, HelpMessage = "Enter the import file path for import")]
	[Parameter(ParameterSetName = 'ExportFile', Mandatory = $true, HelpMessage = "Enter the export file path for export")]
	[string]$listFile,

	[Parameter(Mandatory = $false)]
	[PScredential]$creds,

	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory = $false)]
	[Switch]$DisableSSLVerify,

	# Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
	[Parameter(Mandatory = $false)]
	$logonToken
)

$operationName = $PSCmdlet.ParameterSetName

if ($operationName -eq 'Interactive') {
	Write-Host ""
	Write-Host "Export / Import Platform"
	Write-Host "  1. Import one platform ZIP"
	Write-Host "  2. Import platform ZIPs listed in a file"
	Write-Host "  3. Export one platform"
	Write-Host "  4. Export platforms listed in a file"
	Write-Host "  5. Export all active regular platforms"
	Write-Host "  6. Export all regular platforms"

	do {
		$operationChoice = Read-Host "Select an operation (1-6)"
	} until ($operationChoice -in @('1', '2', '3', '4', '5', '6'))

	$operationName = @{
		'1' = 'Import'
		'2' = 'ImportFile'
		'3' = 'Export'
		'4' = 'ExportFile'
		'5' = 'ExportActive'
		'6' = 'ExportAll'
	}[$operationChoice]

	do {
		$PVWAURL = Read-Host "PVWA address (for example, https://pvwa.example.com/PasswordVault)"
	} until (-not [string]::IsNullOrWhiteSpace($PVWAURL))

	switch ($operationName) {
		'Import' {
			do { $PlatformZipPath = Read-Host "Platform ZIP file path" }
			until (-not [string]::IsNullOrWhiteSpace($PlatformZipPath))
		}
		'ImportFile' {
			do { $listFile = Read-Host "File containing platform ZIP paths" }
			until (-not [string]::IsNullOrWhiteSpace($listFile))
		}
		'Export' {
			do { $PlatformID = Read-Host "Platform ID" }
			until (-not [string]::IsNullOrWhiteSpace($PlatformID))
			do { $PlatformZipPath = Read-Host "Export directory" }
			until (-not [string]::IsNullOrWhiteSpace($PlatformZipPath))
		}
		'ExportFile' {
			do { $listFile = Read-Host "File containing platform IDs" }
			until (-not [string]::IsNullOrWhiteSpace($listFile))
			do { $PlatformZipPath = Read-Host "Export directory" }
			until (-not [string]::IsNullOrWhiteSpace($PlatformZipPath))
		}
		{ $_ -in @('ExportActive', 'ExportAll') } {
			do { $PlatformZipPath = Read-Host "Export directory" }
			until (-not [string]::IsNullOrWhiteSpace($PlatformZipPath))
		}
	}
}

# Normalize the base URL before constructing any API URLs. In the previous
# version this happened after the URLs had already been built, which produced
# double slashes when PVWAURL ended in "/".
$PVWAURL = $PVWAURL.Trim().TrimEnd('/')
if ([string]::IsNullOrWhiteSpace($PVWAURL)) {
	throw "PVWAURL cannot be empty."
}

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL + "/api"
$URL_Authentication = $URL_PVWAAPI + "/auth"
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + "/Logoff"

# URL Methods
# -----------
$URL_GetPlatforms = $URL_PVWAAPI + "/Platforms"
$URL_PlatformDetails = $URL_PVWAAPI + "/Platforms/{0}"
$URL_ExportPlatforms = $URL_PVWAAPI + "/Platforms/{0}/Export"
$URL_ImportPlatforms = $URL_PVWAAPI + "/Platforms/Import"

# Initialize Script Variables
# ---------------------------
$rstusername = $rstpassword = ""

$global:InDebug = ($PSBoundParameters.ContainsKey('Debug') -and $PSBoundParameters['Debug'])
$global:InVerbose = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose'])

$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_DATE = $(Get-Date -Format yyyyMMdd) + "-" + $(Get-Date -Format HHmmss)
$global:LOG_FILE_PATH = Join-Path -Path $ScriptLocation -ChildPath "Export-Import-Platform_$LOG_DATE.log"
$script:TokenWasProvided = $PSBoundParameters.ContainsKey('logonToken') -and -not [string]::IsNullOrEmpty($logonToken)

#region Functions
Function Test-CommandExists {
	Param ($command)
	$oldPreference = $ErrorActionPreference
	$ErrorActionPreference = 'stop'
	try {
		if (Get-Command $command) {
			RETURN $true 
		} 
 } Catch {
		Write-LogMessage -Type Info -Msg "$command does not exist"; RETURN $false 
 } Finally {
		$ErrorActionPreference = $oldPreference 
 }
} #end function test-CommandExists
Function Write-LogMessage {
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
	The type of the message to log (Info, Warning, Error, Debug)
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
		[ValidateSet("Info", "Warning", "Error", "Debug", "Verbose")]
		[String]$type = "Info",
		[Parameter(Mandatory = $false)]
		[String]$LogFile = $LOG_FILE_PATH
	)
	try {
		If ($Header) {
			"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "======================================="
		} ElseIf ($SubHeader) { 
			"------------------------------------" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "------------------------------------"
		}
	
		$msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
		$writeToFile = $true
		# Replace empty message with 'N/A'
		if ([string]::IsNullOrEmpty($Msg)) {
			$Msg = "N/A" 
		}
		# Mask Passwords
		if ($Msg -match '((?:"password"|"secret"|"NewCredentials")\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w!@#$%^&*()-\\\/]+))') {
			$Msg = $Msg.Replace($Matches[2], "****")
		}
		# Check the message type
		switch ($type) {
			"Info" { 
				Write-Host $MSG.ToString()
				$msgToWrite += "[INFO]`t$Msg"
			}
			"Warning" {
				Write-Host $MSG.ToString() -ForegroundColor DarkYellow
				$msgToWrite += "[WARNING]`t$Msg"
			}
			"Error" {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
			}
			"Debug" { 
				if ($InDebug -or $InVerbose) {
					Write-Debug $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
				} else {
					$writeToFile = $False 
				}
			}
			"Verbose" { 
				if ($InVerbose) {
					Write-Verbose $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
				} else {
					$writeToFile = $False 
				}
			}
		}
		
		If ($writeToFile) {
			$msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH 
		}
		If ($Footer) { 
			"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "======================================="
		}
	} catch {
		Write-Error "Error in writing log: $($_.Exception.Message)" 
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Join-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
Function Join-ExceptionMessage {
	<# 
.SYNOPSIS 
	Formats exception messages
.DESCRIPTION
	Formats exception messages
.PARAMETER Exception
	The Exception object to format
#>
	param(
		[Exception]$e
	)

	Begin {
	}
	Process {
		$msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
		while ($e.InnerException) {
			$e = $e.InnerException
			$msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
		}
		return $msg
	}
	End {
	}
}

#endregion

Function import-platform {

	param(
		[string]$PlatformZipPath
	)
	If (Test-Path -LiteralPath $PlatformZipPath -PathType Leaf) {
		Write-LogMessage -Type Debug -Msg "PlatformZipPath: `"$PlatformZipPath`""
		$resolvedZipPath = (Resolve-Path -LiteralPath $PlatformZipPath -ErrorAction Stop).ProviderPath
		$zipContent = [System.IO.File]::ReadAllBytes($resolvedZipPath)
		$importBody = @{ ImportFile = $zipContent; } | ConvertTo-Json -Depth 3 -Compress
		Write-LogMessage -Type Debug -Msg "Import request body created ($($importBody.Length) characters)"
		try {
			$ImportPlatformResponse = Invoke-RestMethod -Method POST -Uri $URL_ImportPlatforms -Headers $logonHeader -ContentType "application/json" -TimeoutSec 2700 -Body $importBody -ErrorAction Stop
			# Get the Platform Name
			$platformDetails = Invoke-RestMethod -Method Get -Uri $($URL_PlatformDetails -f $ImportPlatformResponse.PlatformID) -Headers $logonHeader -ContentType "application/json" -TimeoutSec 2700 -ErrorAction Stop
			If ($platformDetails) {
				Write-LogMessage -Type Debug -Msg "PlatformID: `"$($platformDetails.PlatformID)`""
				Write-LogMessage -Type Debug -Msg "PlatformDetails: "
				ForEach ($detail in $platformDetails.Details.PSObject.Properties) {
					Write-LogMessage -Type Debug -Msg "		$($detail.name): `"$($detail.value)`""
				}
				Write-LogMessage -Type Info -Msg "Platform named `"$($platformDetails.Details.PolicyName)`" with PlatformID `"$($platformDetails.PlatformID)`" was successfully imported and is $(if($platformDetails.Active) { "active" } else { "inactive" })"				
			}		
			return $true
		} catch {
			IF ($_ -match "ITAPS016E" ){
				Write-LogMessage -Type Info -Msg "Platform in file `"$PlatformZipPath`" already exists. To update, delete existing version and import again."
			} else {
				Write-LogMessage -Type Error -Msg "Error while attempting to import `"$PlatformZipPath`""
				try {
					Write-LogMessage -Type Error -Msg "Error Code: `"$($($_.ErrorDetails | ConvertFrom-Json).ErrorCode)`""
					Write-LogMessage -Type Error -Msg "Error Message: `"$($($_.ErrorDetails | ConvertFrom-Json).ErrorMessage)`""
				}
				catch  {
					Write-LogMessage -Type Error -Msg "Error `"$($Error[1].ErrorDetails.Message)`""
				}

			}
			return $false
		}
	} else {
		Write-LogMessage -Type Error -Msg "Platform ZIP file does not exist: `"$PlatformZipPath`""
		return $false
	}
} #end function Import

Function export-platform {

	param(
		[string]$PlatformID
	)

	try {
		$exportURL = $URL_ExportPlatforms -f $PlatformID
		$exportPath = Join-Path -Path $PlatformZipPath -ChildPath ($PlatformID + ".zip")
		Write-LogMessage -Type Debug -Msg "Using URL: $exportURL"
		Write-LogMessage -Type Debug -Msg "Exporting to: $exportPath"
		Invoke-RestMethod -Method POST -Uri $exportURL -Headers $logonHeader -ContentType "application/zip" -TimeoutSec 2700 -OutFile $exportPath -ErrorAction Stop
		if (-not (Test-Path -LiteralPath $exportPath -PathType Leaf) -or (Get-Item -LiteralPath $exportPath).Length -eq 0) {
			throw "PVWA returned no platform ZIP content."
		}
		Write-LogMessage -Type Info -Msg "Successfully exported platform `"$PlatformID`""
		return $true
	} catch {
		Write-LogMessage -Type Error -Msg "Error while attempting to export platformID `"$PlatformID`""
		try {	
			Write-LogMessage -Type Error -Msg "Error Code: `"$($($_.ErrorDetails | ConvertFrom-Json).ErrorCode)`""
			Write-LogMessage -Type Error -Msg "Error Message: `"$($($_.ErrorDetails | ConvertFrom-Json).ErrorMessage)`""
		}
		catch  {
			Write-LogMessage -Type Error -Msg "Error `"$($Error[1].ErrorDetails.Message)`""
		}
		return $false
	}
} #end function Import

Function Get-PlatformsList {
	param(
		[switch]$GetAll
	)

	$idList = @()
	
	try {
		If ($GetAll) {
			$url = $URL_GetPlatforms + "?PlatformType=Regular"
		} else {
			$url = $URL_GetPlatforms + "?Active=True&PlatformType=Regular"
		}
		Write-LogMessage -Type Debug -Msg "Using URL: $url"
		$result = Invoke-RestMethod -Method GET -Uri $url -Headers $logonHeader -ErrorAction Stop

		foreach ($platform in $result.Platforms) {
			$idList += $platform.general.id
		}

		return $idList

	} catch {
		Write-LogMessage -Type Error -Msg "Error while attempting to Get-PlatformsList with `"GetAll`" equal `"$GetAll`""
		try {
			Write-LogMessage -Type Error -Msg "Error Code: `"$($($_.ErrorDetails | ConvertFrom-Json).ErrorCode)`""
			Write-LogMessage -Type Error -Msg "Error Message: `"$($($_.ErrorDetails | ConvertFrom-Json).ErrorMessage)`""
		}
		catch  {
			Write-LogMessage -Type Error -Msg "Error `"$($Error[1].ErrorDetails.Message)`""
		}
	}
} #end function Import



If (Test-CommandExists Invoke-RestMethod) {
	If ($DisableSSLVerify) {
		try {
			Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
			# Using Proxy Default credentials if the Server needs Proxy credentials
			[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
			# Using TLS 1.2 as security protocol verification
			[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
			# Disable SSL Verification
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
		} catch {
			Write-LogMessage -Type Error -Msg "Could not change SSL validation"
			Write-LogMessage -Type Error -Msg (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
			return
		}
	} Else {
		try {
			Write-LogMessage -Type Verbose -Msg "Setting script to use TLS 1.2"
			[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
		} catch {
			Write-LogMessage -Type Error -Msg "Could not change SSL settings to use TLS 1.2"
			Write-LogMessage -Type Error -Msg (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
		}
	}

	# Validate local inputs before prompting for credentials or opening a session.
	$parsedPVWAUri = $null
	if (-not [Uri]::TryCreate($PVWAURL, [UriKind]::Absolute, [ref]$parsedPVWAUri) -or
		($parsedPVWAUri.Scheme -ne 'http' -and $parsedPVWAUri.Scheme -ne 'https')) {
		Write-LogMessage -Type Error -Msg "PVWAURL must be an absolute HTTP or HTTPS URL."
		return
	}
	if ($operationName -in @('Export', 'ExportFile', 'ExportActive', 'ExportAll')) {
		if (-not (Test-Path -LiteralPath $PlatformZipPath -PathType Container)) {
			Write-LogMessage -Type Error -Msg "Export directory does not exist: `"$PlatformZipPath`""
			return
		}
	}
	if ($operationName -in @('ImportFile', 'ExportFile')) {
		if (-not (Test-Path -LiteralPath $listFile -PathType Leaf)) {
			Write-LogMessage -Type Error -Msg "List file does not exist: `"$listFile`""
			return
		}
	}

	Write-LogMessage -Type Info -Msg "Export / Import Platform: Script Started"

	#region [Logon]
	# Get Credentials to Login
	# ------------------------
	$caption = "Export / Import Platform"

	If (![string]::IsNullOrEmpty($logonToken)) {
		if ($logonToken.GetType().name -eq "String") {
			$logonHeader = @{Authorization = $logonToken }
		} else {
			$logonHeader = $logonToken
  }
	} else {
		$msg = "Enter your User name and Password" 
		if ($Null -eq $creds) {
			$creds = $Host.UI.PromptForCredential($caption, $msg, "", "")
		}
		if ($null -ne $creds) {
			$rstusername = $creds.UserName
			$rstpassword = $creds.GetNetworkCredential().password

		} else {
			return 
		}

		# Create the POST Body for the Logon
		# ----------------------------------
		$logonBody = @{ username = $rstusername; password = $rstpassword; concurrentSession = 'true' }
		$logonBody = $logonBody | ConvertTo-Json
		try {
			# Logon
			Write-LogMessage -Type Debug -Msg "Logon URL: $URL_Logon" 
			Write-LogMessage -Type Debug -Msg "Logon request body omitted because it contains credentials"
			$logonToken = Invoke-RestMethod -Method Post -Uri $URL_Logon -Body $logonBody -ContentType "application/json" -ErrorAction Stop
			Write-LogMessage -Type Debug -Msg "Logon succeeded; token omitted from log"
		} catch {
			Write-LogMessage -Type Error -Msg $_.Exception.Response.StatusDescription
			$logonToken = ""
		}
		If ($logonToken -eq "") {
			Write-LogMessage -Type Error -Msg "Logon Token is Empty - Cannot login"
			return
		}
	
		# Create a Logon Token Header (This will be used through out all the script)
		# ---------------------------
		$logonHeader = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
		$logonHeader.Add("Authorization", $logonToken)
		#endregion
	}
	switch ($operationName) {
		"Import" {
			Write-LogMessage -Type Debug -Msg "In `"Import`" PlatformZipPath : $PlatformZipPath"
			[void](import-platform $PlatformZipPath)
		}

		"ImportFile" {
			Write-LogMessage -Type Debug -Msg "In `"ImportFile`" listFile : $listFile"
			foreach ($line in Get-Content $listFile) {
				Write-LogMessage -Type Verbose -Msg "Trying to import $line" 
				if (![string]::IsNullOrEmpty($line)) {
					[void](import-platform $line.Trim())
    }
			} 
		}

		"Export" {
			Write-LogMessage -Type Debug -Msg "In `"Export`" PlatformID : $PlatformID"
			if (![string]::IsNullOrEmpty($PlatformID)) {
				export-platform $PlatformID
   }
			
		}

		"ExportFile" {
			Write-LogMessage -Type Debug -Msg "In `"ExportFile`" PlatformZipPath : $PlatformZipPath"
			$exportManifest = Join-Path -Path $PlatformZipPath -ChildPath '_Exported.txt'
			$null | Out-File -FilePath $exportManifest -Force
			foreach ($line in Get-Content $listFile) {
				$platformToExport = $line.Trim()
				Write-LogMessage -Type Verbose -Msg "Trying to export PlatformID `"$platformToExport`"" 
				if (![string]::IsNullOrEmpty($platformToExport)) {
					if (export-platform $platformToExport) {
						Join-Path -Path $PlatformZipPath -ChildPath ($platformToExport + '.zip') | Out-File -FilePath $exportManifest -Append
					}
				}
			} 
	
		}
		{ ($_ -eq "ExportActive") -or ($_ -eq "ExportAll") } {
			Write-LogMessage -Type Debug -Msg "In `"ExportActive or ExportAll`" PlatformZipPath : $PlatformZipPath"
			$platforms = Get-PlatformsList -GetAll:$(($operationName -eq "ExportAll"))
			$exportManifest = Join-Path -Path $PlatformZipPath -ChildPath '_Exported.txt'
			$null | Out-File -FilePath $exportManifest -Force
			foreach ($line in $platforms) {
				Write-LogMessage -Type Verbose -Msg "Trying to export PlatformID `"$line`"" 
				if (![string]::IsNullOrEmpty($line)) { 
					if (export-platform $line) {
						Join-Path -Path $PlatformZipPath -ChildPath ($line + '.zip') | Out-File -FilePath $exportManifest -Append
					}
				}		
			} 

		}
	}
	# Logoff the session

	# ------------------
	Write-LogMessage -Type Info -Msg "Logoff Session..."
	If ($script:TokenWasProvided) {
		Write-LogMessage -Type Info -Msg "LogonToken passed, session NOT logged off"
	} else {
		try {
			Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $logonHeader -ContentType "application/json" -ErrorAction Stop | Out-Null
		} catch {
			Write-LogMessage -Type Warning -Msg "Logoff failed: $($_.Exception.Message)"
		}
	}
	
} else {
	Write-LogMessage -Type Error -Msg "This script requires PowerShell version 3 or above"
}

Write-LogMessage -Type Info -Msg "Export / Import Platform: Script Finished" 
