<#
	.SYNOPSIS
	The script downloads VLC media player setup file and install automatically newer version.
	
	.DESCRIPTION
	1) Script downloads VLC media palyer setup msi from internet and compares it to the currently installed VLC media player
	2) If update is necessary (internet version is greater than), the script will install/upgrade VLC media player
	
	Author(s):
	2023-03-21 CandymanRabbit
	
	.INPUTS
	This script does not accept input
	
	.OUTPUTS
	This script does not return anything
	
	.PARAMETER Force
	This will force download of MSI and install if necessary.
#>
[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)]
    [Switch]$Force = $false
)

#region Cleanup-DownloadFolder
function Cleanup-DownloadFolder {
    try {
        if (Test-Path $DownloadDir) {
            $Items = Get-ChildItem $DownloadDir
            if (-not [string]::IsNullOrEmpty($Items)) {
                foreach ($Item in $Items) {
                    Write-Log "Removing item $($item)"
                    Remove-Item $item.fullname -Recurse -Force | Out-Null
                }
            } else {
                Write-Log "Download folder does not contain any items."
            }
        } else {
            Write-Log "Download folder not found"
        }
    } catch {
        Write-Log "$($_.Exception)"
    }
}
#end region

#region Get-InstalledApplications
function Get-InstalledApplications {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String[]]$Name
    )
    try {
        If ($name) {
            Write-Log -Message "Getting information for installed Application Name(s) [$($name -join ', ')]..."
        }
        [String[]]$regKeyApplications = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'

        ## Enumerate the installed applications from the registry for applications that have the "DisplayName" property
        [PSObject[]]$regKeyApplication = @()
        ForEach ($regKey in $regKeyApplications) {
            If (Test-Path -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath') {
                [PSObject[]]$UninstallKeyApps = Get-ChildItem -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath'
                ForEach ($UninstallKeyApp in $UninstallKeyApps) {
                    Try {
                        [PSObject]$regKeyApplicationProps = Get-ItemProperty -LiteralPath $UninstallKeyApp.PSPath -ErrorAction 'Stop'
                        If ($regKeyApplicationProps.DisplayName) {
                            [PSObject[]]$regKeyApplication += $regKeyApplicationProps
                        }
                    }
                    Catch {
                        Write-Log -Message "Unable to enumerate properties from registry key path [$($UninstallKeyApp.PSPath)]."
                        Continue
                    }
                }
            }
        }
        If ($ErrorUninstallKeyPath) {
            Write-Log -Message "The following error(s) took place while enumerating installed applications from the registry."
        }

        ## Create a custom object with the desired properties for the installed applications and sanitize property details
        [PSObject[]]$installedApplication = @()
        ForEach ($regKeyApp in $regKeyApplication) {
            Try {
                [String]$appDisplayName = ''
                [String]$appDisplayVersion = ''
                [String]$appPublisher = ''

                ## Remove any control characters which may interfere with logging and creating file path names from these variables
                $appDisplayName = $regKeyApp.DisplayName -replace '[^\p{L}\p{Nd}\p{Z}\p{P}]', ''
                $appDisplayVersion = $regKeyApp.DisplayVersion -replace '[^\p{L}\p{Nd}\p{Z}\p{P}]', ''
                $appPublisher = $regKeyApp.Publisher -replace '[^\p{L}\p{Nd}\p{Z}\p{P}]', ''


                ## Determine if application is a 64-bit application
                [Boolean]$Is64BitApp = If (($is64Bit) -and ($regKeyApp.PSPath -notmatch '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node')) {
                    $true
                }
                Else {
                    $false
                }
                If ($name) {
                    ## Verify if there is a match with the application name(s) passed to the script
                    ForEach ($application in $Name) {
                        $applicationMatched = $false
                        #  Check for a contains application name match
                        If ($regKeyApp.DisplayName -match [RegEx]::Escape($application)) {
                            $applicationMatched = $true
                            Write-Log -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using contains matching for search term [$application]." 
                        }

                        If ($applicationMatched) {
                            $installedApplication += New-Object -TypeName 'PSObject' -Property @{
                                UninstallSubkey    = $regKeyApp.PSChildName
                                ProductCode        = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) {
                                    $regKeyApp.PSChildName
                                }
                                Else {
                                    [String]::Empty
                                }
                                DisplayName        = $appDisplayName
                                DisplayVersion     = $appDisplayVersion
                                UninstallString    = $regKeyApp.UninstallString
                                InstallSource      = $regKeyApp.InstallSource
                                InstallLocation    = $regKeyApp.InstallLocation
                                InstallDate        = $regKeyApp.InstallDate
                                Publisher          = $appPublisher
                                Is64BitApplication = $Is64BitApp
                            }
                        }
                    }
                }                        
            } Catch {
                $_
                Write-Log -Message "Failed to resolve application details from registry for [$appDisplayName]."
                Continue
            }
        }
        If (-not $installedApplication) {
            Write-Log -Message 'Found no application based on the supplied parameters.'
        }

        Write-Output -InputObject ($installedApplication)
    } catch {
     return $_
    }
}
### CONTINUE HERE ###
        
#region Install-Application
function Install-MSIApplication {
    param(
        [parameter(Mandatory=$true)] 
        [ValidateNotNullOrEmpty()] 
        [System.IO.FileInfo] $MSIPATH
)
    try {
        if (Test-Path $MSIPATH) {
            Write-Log "[$($MSIPATH)] is a valid fully qualified path, continue."
            Start-Process msiexec -ArgumentList "/I $($MSIPATH) /QN REBOOT=ReallySuppress /l*v $($LogPath)\VLC-MSI-Install.log"
        } else {
            Write-Log "[$($MSIPATH)] is NOT a valid fully qualified path."
        }
    } catch {
        Write-Log "$($_.Exception)"
        exit
    }
}
#end region

#region Download-Application
function Download-VLCApplication {

    try{
        if (-not (Test-Path $DownloadDir)) {
            Write-Log "Download directory not found. Creating donwload directory."
            New-Item -Path $DownloadDir -ItemType Directory -Force
            Write-Log "Download directory created succesfully."
        }
        Write-Log "Trying to download VLC media player file $vlcFile from $vlcURL"
	    Invoke-WebRequest -uri $downloadurl -outfile "$DownloadDir\$tmpdownloadfile" -erroraction stop
	    Write-Log "VLC media player downloaded"
    }catch{
	    Write-Log "$($_.Exception)"
	    Exit
    }
}
#end region

#region Get-MSIDataTableVersion
function Get-MSIDataTableVersion {
    <#
    .SYNOPSIS
    Function to Check Version of an MSI file.
    
    .DESCRIPTION
    Function to Check Version of an MSI file for comparision in other scripts.
    Accepts path to single file.
    
    .PARAMETER msifile
    Specifies the path to MSI file.
    
    .EXAMPLE
    PS> Which-MSIVersion -msifile $msifile
    68.213.49193
    
    .NOTES
    General notes
    #>
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Specifies path to MSI file.')]
        [ValidateScript({ if ($_.EndsWith('.msi')) { $true } else { throw ("{0} must be an '*.msi' file." -f $_) }})]
        [String[]] $msifile
    )

    $invokemethod = 'InvokeMethod'
    try {

        #calling com object
        $FullPath = (Resolve-Path -Path $msifile).Path
        $windowsInstaller = New-Object -ComObject WindowsInstaller.Installer

        ## opening database from file
        $database = $windowsInstaller.GetType().InvokeMember(
            'OpenDatabase', $invokemethod, $Null, 
            $windowsInstaller, @($FullPath, 0)
        )

        ## select productversion from database
        $q = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"
        $View = $database.GetType().InvokeMember(
            'OpenView', $invokemethod, $Null, $database, ($q)
        )

        ##execute
        $View.GetType().InvokeMember('Execute', $invokemethod, $Null, $View, $Null)

        ## fetch
        $record = $View.GetType().InvokeMember(
            'Fetch', $invokemethod, $Null, $View, $Null
        )

        ## write to variable
        $productVersion = $record.GetType().InvokeMember(
            'StringData', 'GetProperty', $Null, $record, 1
        )

        $View.GetType().InvokeMember('Close', $invokemethod, $Null, $View, $Null)


        ## return productversion
        return $productVersion

    }
    catch {
        throw 'Failed to get MSI file version the error was: {0}.' -f $_
    }
}
#end region

#region Write-Log
function Write-Log {
	param(
        [Parameter(Mandatory=$true)]
        [array]$Message
)
	$TimeStamp = get-date -f "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$TimeStamp] :: $Message"
	"[$TimeStamp] :: $Message" | out-file $LogPath\$LogFileName -append
}
#end region

#region Import-ini
Function Import-Ini ([string]$Path = $(Read-Host "Please supply a value for the Path parameter")) {
	try {
    # initialize hash table
	$ini = @{}
	if (Test-Path -Path $Path) {
		# read configuration file
		$data = Get-Content $Path -Encoding String
		# loop through configuration file
		foreach ($line in $data) {
			# remove spaces
			$line = $line.Trim()
			# check if line actually contains data
			if ($line.length -gt 0) {
				# check if line is commented out with ;
				if ($line.substring(0,1) -ne ";") {
					# Read data into hash table if line has a match for [CATEGORY]
					if ($line -match "^\[(.+)\]$") {
						$Category = $matches[1]
						$ini.$Category = @{}
					}
					# Read data into hash table if line has a match for Name=Data
					if ($line -match "(.+)=(.+)") {
						$Key,$Value = $matches[1..2]
						$ini.$Category.$Key = $Value
					}
				}
			}
		}
	} else {
		Write-Host "File not found: $Path" -ForegroundColor Red
	}
	# return hash table
	$ini
    } catch {
        Write-Host "$($_.Exception)"
    }
}
#end region

##*===============================================
##* SCRIPT STARTS HERE
##*===============================================

try {
    $CurrentLocation = Get-Location
    $bScriptCompletedSuccessfully = $false

    if ($psISE.CurrentFile.DisplayName -ne $null) {
        $ScriptPath = Split-Path $psise.CurrentFile.FullPath
        $ScriptName = ($psise.CurrentFile.FullPath).Replace("$ScriptPath\", '')
    } else {
        $ScriptName = "$($MyInvocation.MyCommand.Name)"
        $ScriptPath = Split-Path -Parent $PSCommandPath
    }
    
    $ConfigurationFile = Get-ChildItem $ScriptPath -Filter *.ini
    
    # Read Ini contents into a hash table
    if (Test-Path($ConfigurationFile)) {
	    Write-Host " - Reading configuration from: $ConfigurationFile"
	    $ConfigurationData = Import-Ini $ConfigurationFile
    } else {
	    Write-Host "ERROR: Configuration file not found: $ConfigurationFile" -ForegroundColor Red
        break
    }

    ##*===============================================
    ##* VARIABLE DECLARATION
    ##*===============================================

    # General variables
    $DownloadDir = $($ConfigurationData."General"."DownloadDir")
    $EnableCustomLogDir = $($ConfigurationData."General"."EnableCustomLogDir")
    $CustomLogDir = $($ConfigurationData."General"."CustomLogDir")
    $DefaultLogPath = $ScriptPath
    $LogFileName = ($ScriptName.Replace('.ps1','.log'))

    ## Variables: VLC 
    $vlcURL = "https://download.videolan.org/vlc/last/win64/"
    $getHTML = Invoke-Webrequest -Uri $vlcURL
    $vlcFile = ($getHTML.ParsedHtml.getElementsByTagName("a")| Where {$_.innerhtml -like 'vlc-*.msi'}).innertext
    $downloadurl = "https://download.videolan.org/vlc/last/win64/$vlcFile"
    $tmpdownloadfile = "tmp_$vlcFile"

    if ($EnableCustomLogDir -eq 'true') {
        $LogPath = $CustomLogDir
    } else {
        $LogPath = $DefaultLogPath
    }

    ##*===============================================
    ##* END VARIABLE DECLARATION
    ##*===============================================
    
    ## Get currently installed VLC
    $CurrentVlc = Get-InstalledApplications -Name VLC

    ## Compare internet media to installed version by filename
    $vlcFile = $vlcFile.Split('-')[1]
    If (([version]$CurrentVlc.displayversion -le [version]$vlcFile) -or ($force)) {
        
        ## Cleanup download folder
        Cleanup-DownloadFolder

        ## Start downloading
        Download-VLCApplication
 	
	    if (Test-Path $DownloadDir\$tmpdownloadfile) {
                # Validate MSI version info
                Write-Log "Extracting version info from file $tmpdownloadfile"
                [string]$webversion = Get-MSIDataTableVersion $DownloadDir\$tmpdownloadfile
                [version]$newvlc = $webversion
                if ($newvlc -eq $null) {
                    Write-Log "We couldn't retrieve versioninfo from new file! Sorry!"
                    exit
                }
	            Write-Log "Version info for the downloaded file is: $($newvlc.tostring())"
	    }

        ## Double check 
        If ([version]$CurrentVlc.displayversion -le $newvlc) {
            Install-MSIApplication -MSIPATH $DownloadDir\$tmpDownloadFile
        } else {
            Write-Log "Currently installed version is up to date."
        }
    } else {
        Write-Log "Currently installed version should be up to date. Run script with -Force parameter to force download msi."
    }
} catch {
    Write-Log "$($_.Exception)"
    exit
}
Cleanup-DownloadFolder
Write-Log "Script completed successfully."