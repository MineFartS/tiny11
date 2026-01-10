
param(
    $Scratch = "$env:TEMP\tiny11"
)

#===========================================================================================================
# Force Elevation

# Check and run the script as admin if required
$adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if (! $myWindowsPrincipal.IsInRole($adminRole)) {
    Write-Output "Restarting Tiny11 image creator as admin in a new window, you can close this one."
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    $newProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($newProcess);
    exit
}

#===========================================================================================================
# Functions
function Set-RegistryValue {
    param (
        [string]$path,
        [string]$name,
        [string]$type,
        [string]$value
    )
    try {
        & 'reg' 'add' $path '/v' $name '/t' $type '/d' $value '/f' | Out-Null
        Write-Output "Set registry value: $path\$name"
    } catch {
        Write-Output "Error setting registry value: $_"
    }
}

function Remove-RegistryValue {
    param (
		[string]$path
	)
	try {
		& 'reg' 'delete' $path '/f' | Out-Null
		Write-Output "Removed registry value: $path"
	} catch {
		Write-Output "Error removing registry value: $_"
	}
}

function Repair-Permissions {
    param(
        [string] $Path
    )

    Set-ItemProperty `
        -Path $Path `
        -Name IsReadOnly `
        -Value $false `
        | Out-Null

    takeown.exe /F $Path
    icacls.exe $Path /grant "$($adminGroup.Value):(F)"
}

function Mount-Registry {
    reg load HKLM\zCOMPONENTS $Scratch\scratchdir\Windows\System32\config\COMPONENTS | Out-Null
    reg load HKLM\zDEFAULT $Scratch\scratchdir\Windows\System32\config\default | Out-Null
    reg load HKLM\zNTUSER $Scratch\scratchdir\Users\Default\ntuser.dat | Out-Null
    reg load HKLM\zSOFTWARE $Scratch\scratchdir\Windows\System32\config\SOFTWARE | Out-Null
    reg load HKLM\zSYSTEM $Scratch\scratchdir\Windows\System32\config\SYSTEM | Out-Null
}

function Dismount-Registry {
    reg unload HKLM\zCOMPONENTS | Out-Null
    reg unload HKLM\zDEFAULT | Out-Null
    reg unload HKLM\zNTUSER | Out-Null
    reg unload HKLM\zSOFTWARE | Out-Null
    reg unload HKLM\zSYSTEM | Out-Null
}

#===========================================================================================================
# Prepare the Terminal

# Set the window title
$Host.UI.RawUI.WindowTitle = "Tiny11 Image Creator"

#
Clear-Host

#===========================================================================================================
# Create Scratch Directories

Remove-Item `
    -Path $Scratch `
    -Verbose -Recurse -Force

New-Item `
    -ItemType Directory `
    -Force `
    -Path "$Scratch\tiny11\sources" `
    | Out-Null

New-Item `
    -ItemType Directory `
    -Force `
    -Path "$Scratch\scratchdir" `
    | Out-Null

#===========================================================================================================
# Download,Mount & extract the Windows 11 Installer ISO

#
Add-Type -AssemblyName System.Windows.Forms
$fileDialog = New-Object System.Windows.Forms.OpenFileDialog
$fileDialog.InitialDirectory = "$env:USERPROFILE\Downloads"
$fileDialog.Filter = 'ISO Files (*.iso)|*.iso|All Files (*.*)|*.*'
$fileDialog.Title = 'Please select an ISO file to mount'
$fileDialog.ShowHelp = $true
$fileDialog.ShowDialog() | Out-Null

#===========================================================================================================
# Download & Extract the Windows 10 Installer ZIP
    
Invoke-WebRequest `
    -Uri "https://github.com/MineFartS/tiny11/raw/refs/heads/master/Win10Setup.zip" `
    -OutFile "$Scratch\Win10Setup.zip"

Expand-Archive `
    -Path "$Scratch\Win10Setup.zip" `
    -DestinationPath "$Scratch\tiny11" `
    -Force -Verbose

#===========================================================================================================

# Mount the ISO and get the assigned drive letter
$mountResult = Mount-DiskImage `
    -ImagePath $fileDialog.FileName `
    -PassThru

#
$ISOmnt = ($mountResult | Get-Volume).DriveLetter

# Copy Windows 11 Install Image
Copy-Item `
    -Path $ISOmnt':\sources\install.wim' `
    -Destination "$Scratch\tiny11\sources\install.wim" `
    -Force -Verbose

# Unmount the ISO
Get-Volume `
    -DriveLetter $ISOmnt `
    | Get-DiskImage `
    | Dismount-DiskImage

#===========================================================================================================

Write-Output "Downloading 'oscdimg.exe' ..."
Invoke-WebRequest `
    -Uri "https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe" `
    -OutFile "$Scratch\oscdimg.exe"

#===========================================================================================================
# Mount Windows 11 Image

#
Repair-Permissions "$Scratch\tiny11\sources\install.wim"

# Find Index # for Windows 11 Pro
$index = ( `
    (Get-WindowsImage -ImagePath "$Scratch\tiny11\sources\install.wim") `
    | Where-Object ImageName -eq 'Windows 11 Pro' `
).ImageIndex

#
Mount-WindowsImage `
    -ImagePath "$Scratch\tiny11\sources\install.wim" `
    -Index $index `
    -Path "$Scratch\scratchdir"

#===========================================================================================================

#
$packagePrefixes = @(
    'AppUp.IntelManagementandSecurityStatus',
    'Clipchamp.Clipchamp', 
    'DolbyLaboratories.DolbyAccess',
    'DolbyLaboratories.DolbyDigitalPlusDecoderOEM',
    'Microsoft.BingNews',
    'Microsoft.BingSearch',
    'Microsoft.BingWeather',
    'Microsoft.Copilot',
    'Microsoft.Windows.CrossDevice',
    'Microsoft.GamingApp',
    'Microsoft.GetHelp',
    'Microsoft.Getstarted',
    'Microsoft.Microsoft3DViewer',
    'Microsoft.MicrosoftOfficeHub',
    'Microsoft.MicrosoftSolitaireCollection',
    'Microsoft.MicrosoftStickyNotes',
    'Microsoft.MixedReality.Portal',
    'Microsoft.MSPaint',
    'Microsoft.Office.OneNote',
    'Microsoft.OfficePushNotificationUtility',
    'Microsoft.OutlookForWindows',
    'Microsoft.Paint',
    'Microsoft.People',
    'Microsoft.PowerAutomateDesktop',
    'Microsoft.SkypeApp',
    'Microsoft.StartExperiencesApp',
    'Microsoft.Todos',
    'Microsoft.Wallet',
    'Microsoft.Windows.DevHome',
    'Microsoft.Windows.Copilot',
    'Microsoft.Windows.Teams',
    'Microsoft.WindowsAlarms',
    'Microsoft.WindowsCamera',
    'microsoft.windowscommunicationsapps',
    'Microsoft.WindowsFeedbackHub',
    'Microsoft.WindowsMaps',
    'Microsoft.WindowsSoundRecorder',
    'Microsoft.WindowsTerminal',
    'Microsoft.Xbox.TCUI',
    'Microsoft.XboxApp',
    'Microsoft.XboxGameOverlay',
    'Microsoft.XboxGamingOverlay',
    'Microsoft.XboxIdentityProvider',
    'Microsoft.XboxSpeechToTextOverlay',
    'Microsoft.YourPhone',
    'Microsoft.ZuneMusic',
    'Microsoft.ZuneVideo',
    'MicrosoftCorporationII.MicrosoftFamily',
    'MicrosoftCorporationII.QuickAssist',
    'MSTeams',
    'MicrosoftTeams', 
    'Microsoft.WindowsTerminal',
    'Microsoft.549981C3F5F10'
)

#
dism.exe `
    /English `
    "/image:$($Scratch)\scratchdir" `
    /Get-ProvisionedAppxPackages `
    | ForEach-Object {
        if ($_ -match 'PackageName : (.*)') {
            
            #
            $packageName = $matches[1]

            #
            if ($packagePrefixes -contains ($packagePrefixes | Where-Object { $packageName -like "*$_*" })) {
                
                Write-Output "Removing Package '$packageName' ..."

                dism.exe `
                    /English `
                    "/image:$Scratch\scratchdir" `
                    /Remove-ProvisionedAppxPackage `
                    "/PackageName:$package"
                    
            }

        }

    }

Write-Output "Removing Edge ..."

Remove-Item `
    -Path "$Scratch\scratchdir\Program Files (x86)\Microsoft\Edge" `
    -Recurse -Force | Out-Null

Remove-Item `
    -Path "$Scratch\scratchdir\Program Files (x86)\Microsoft\EdgeUpdate" `
    -Recurse -Force | Out-Null

Remove-Item `
    -Path "$Scratch\scratchdir\Program Files (x86)\Microsoft\EdgeCore" `
    -Recurse -Force | Out-Null

Repair-Permissions "$Scratch\scratchdir\Windows\System32\Microsoft-Edge-Webview"
Remove-Item `
    -Path "$Scratch\scratchdir\Windows\System32\Microsoft-Edge-Webview" `
    -Recurse -Force | Out-Null

Write-Output "Removing OneDrive ..."

#
Repair-Permissions "$Scratch\scratchdir\Windows\System32\OneDriveSetup.exe"
Remove-Item `
    -Path "$Scratch\scratchdir\Windows\System32\OneDriveSetup.exe" `
    -Force | Out-Null

Write-Output "Loading registry ..."

Mount-Registry

Write-Output "Bypassing system requirements ..."
Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassCPUCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassRAMCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassSecureBootCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassStorageCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassTPMCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\MoSetup' 'AllowUpgradesWithUnsupportedTPMOrCPU' 'REG_DWORD' '1'

Write-Output "Disabling Sponsored Apps ..."
Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'OemPreInstalledAppsEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'PreInstalledAppsEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SilentInstalledAppsEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'ContentDeliveryAllowed' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' 'ConfigureStartPins' 'REG_SZ' '{"pinnedList": [{}]}'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'FeatureManagementEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'PreInstalledAppsEverEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SoftLandingEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContentEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-310093Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338388Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338389Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-338393Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353694Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SubscribedContent-353696Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' 'SystemPaneSuggestionsEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\PushToInstall' 'DisablePushToInstall' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\MRT' 'DontOfferThroughWUAU' 'REG_DWORD' '1'
Remove-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions'
Remove-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableConsumerAccountStateContent' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableCloudOptimizedContent' 'REG_DWORD' '1'

Write-Output "Enabling Local Accounts on OOBE ..."
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' 'BypassNRO' 'REG_DWORD' '1'

Copy-Item `
    -Path "$Scratch\autounattend.xml" `
    -Destination "$Scratch\scratchdir\Windows\System32\Sysprep\autounattend.xml" `
    -Force | Out-Null

Write-Output "Disabling Reserved Storage ..."
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' 'ShippedWithReserves' 'REG_DWORD' '0'

Write-Output "Disabling BitLocker Device Encryption ..."
Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Control\BitLocker' 'PreventDeviceEncryption' 'REG_DWORD' '1'

Write-Output "Disabling Chat icon ..."
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' 'ChatIcon' 'REG_DWORD' '3'
Set-RegistryValue 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarMn' 'REG_DWORD' '0'

Write-Output "Removing Edge related registries ..."
Remove-RegistryValue "HKEY_LOCAL_MACHINE\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge"
Remove-RegistryValue "HKEY_LOCAL_MACHINE\zSOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update"

Write-Output "Disabling OneDrive folder backup ..."
Set-RegistryValue "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" "REG_DWORD" "1"

Write-Output "Disabling Telemetry ..."
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy' 'HasAccepted' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Input\TIPC' 'Enabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' 'RestrictImplicitInkCollection' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization' 'RestrictImplicitTextCollection' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' 'HarvestContacts' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Software\Microsoft\Personalization\Settings' 'AcceptedPrivacyPolicy' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSYSTEM\ControlSet001\Services\dmwappushservice' 'Start' 'REG_DWORD' '4'

Write-Output "Preventing installation of DevHome and Outlook ..."
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate' 'workCompleted' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate' 'workCompleted' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate' 'workCompleted' 'REG_DWORD' '1'
Remove-RegistryValue 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate'
Remove-RegistryValue 'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate'

Write-Output "Disabling Copilot ..."
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' 'TurnOffWindowsCopilot' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Edge' 'HubsSidebarEnabled' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableSearchBoxSuggestions' 'REG_DWORD' '1'

Write-Output "Preventing installation of Teams ..."
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Teams' 'DisableInstallation' 'REG_DWORD' '1'

Write-Output "Preventing installation of New Outlook ..."
Set-RegistryValue 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Mail' 'PreventRun' 'REG_DWORD' '1'

Write-Host "Deleting scheduled task definition files ..."
$tasksPath = "$Scratch\scratchdir\Windows\System32\Tasks"

# Application Compatibility Appraiser
Remove-Item `
    -Path "$tasksPath\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" `
    -Force -ErrorAction SilentlyContinue

# Customer Experience Improvement Program (removes the entire folder and all tasks within it)
Remove-Item `
    -Path "$tasksPath\Microsoft\Windows\Customer Experience Improvement Program" `
    -Recurse -Force -ErrorAction SilentlyContinue

# Program Data Updater
Remove-Item `
    -Path "$tasksPath\Microsoft\Windows\Application Experience\ProgramDataUpdater" `
    -Force -ErrorAction SilentlyContinue

# Chkdsk Proxy
Remove-Item `
    -Path "$tasksPath\Microsoft\Windows\Chkdsk\Proxy" `
    -Force -ErrorAction SilentlyContinue

# Windows Error Reporting (QueueReporting)
Remove-Item `
    -Path "$tasksPath\Microsoft\Windows\Windows Error Reporting\QueueReporting" `
    -Force `
    -ErrorAction SilentlyContinue

Write-Host "Unmounting Registry ..."
Dismount-Registry

Write-Output "Cleaning up image ..."
dism.exe `
    "/Image:$Scratch\scratchdir" `
    /Cleanup-Image `
    /StartComponentCleanup `
    /ResetBase

#
Dismount-WindowsImage `
    -Path $Scratch\scratchdir `
    -Save

Write-Host "Exporting image ..."
Dism.exe `
    /Export-Image `
    "/SourceImageFile:$Scratch\tiny11\sources\install.wim" `
    "/SourceIndex:$index" `
    "/DestinationImageFile:$Scratch\tiny11\sources\install2.wim" `
    "/Compress:recovery"

Remove-Item `
    -Path "$Scratch\tiny11\sources\install.wim" `
    -Force | Out-Null

Rename-Item `
    -Path "$Scratch\tiny11\sources\install2.wim" `
    -NewName "install.wim" `
    | Out-Null

Write-Output "Mounting boot image ..."
Repair-Permissions "$Scratch\tiny11\sources\boot.wim"

Mount-WindowsImage `
    -ImagePath "$Scratch\tiny11\sources\boot.wim" `
    -Index 2 `
    -Path "$Scratch\scratchdir"

Write-Output "Loading registry..."
Mount-Registry

Write-Output "Bypassing system requirements ..."
Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV1' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' 'SV2' 'REG_DWORD' '0'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassCPUCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassRAMCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassSecureBootCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassStorageCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\LabConfig' 'BypassTPMCheck' 'REG_DWORD' '1'
Set-RegistryValue 'HKLM\zSYSTEM\Setup\MoSetup' 'AllowUpgradesWithUnsupportedTPMOrCPU' 'REG_DWORD' '1'

Write-Output "Unmounting Registry..."
Dismount-Registry

Write-Output "Unmounting image..."
Dismount-WindowsImage `
    -Path "$Scratch\scratchdir" `
    -Save

Write-Output "Copying unattended file for bypassing MS account on OOBE..."
Copy-Item `
    -Path "$Scratch\autounattend.xml" `
    -Destination "$Scratch\tiny11\autounattend.xml" `
    -Force | Out-Null

& "$Scratch\oscdimg.exe" `
    '-m' '-o' '-u2' '-udfver102' `
    "-bootdata:2#p0,e,b$Scratch\tiny11\boot\etfsboot.com#pEF,e,b$Scratch\tiny11\efi\microsoft\boot\efisys.bin" `
    "$Scratch\tiny11" `
    "$(Get-Location)\tiny11.iso"

# Finishing up
Write-Output "Performing Cleanup ..."
Remove-Item `
    -Path $Scratch `
    -Recurse -Force | Out-Null

Write-Output "Creation completed!"
Pause