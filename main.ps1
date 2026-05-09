#===========================================================================================================
# Force Elevation

# Check and run the script as admin if required
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if (! $myWindowsPrincipal.IsInRole($adminRole)) {
    $newProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    $newProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($newProcess) | Out-Null
    exit
}

#===========================================================================================================
# Prepare the Terminal

$Host.UI.RawUI.WindowTitle = "Tiny11 Image Creator"

Clear-Host

Set-Location $PSScriptRoot

Write-Host @"
.---------------------------------------------------.
|ooooooooooo o88                           oo    oo |
|88  888  88 oooo  oo oooooo oooo   oooo o888  o888 |
|    888      888   888   888 888   888   888   888 |
|    888      888   888   888  888 888    888   888 |
|   o888o    o888o o888o o888o   8888    o888o o888o|
|                             o8o888                |
'---------------------------------------------------'
"@

#===========================================================================================================
# Prompt for the Windows 11 Installer ISO

Add-Type -AssemblyName System.Windows.Forms

$OpenDialog = New-Object System.Windows.Forms.OpenFileDialog
$SaveDialog = New-Object System.Windows.Forms.SaveFileDialog

@($OpenDialog, $SaveDialog) | ForEach-Object {
    $_.InitialDirectory = "$env:USERPROFILE\Downloads"
    $_.Filter = 'ISO Files (*.iso)|*.iso|All Files (*.*)|*.*'
    $_.ShowHelp = $true
}

$OpenDialog.Title = 'Please select an ISO file to mount'
$OpenDialog.ShowDialog() | Out-Null
$Source = $OpenDialog.FileName

$SaveDialog.Title = 'Where should the output ISO be saved'
$SaveDialog.ShowDialog() | Out-Null
$Output = $SaveDialog.FileName

#===========================================================================================================
# Init Submodules

Write-Host "`nInitializing Submodules ..."

git.exe submodule update --init --recursive | Out-Null

#===========================================================================================================
# Create Scratch Directories

Write-Host "`nPreparing Temporary Directory ..."

$Scratch = "$PSScriptRoot\.Scratch"

takeown.exe /f $Scratch /r /d Y >$null
icacls.exe $Scratch /t /c /grant Administrators:F >$null

Remove-Item `
    -Path $Scratch `
    -Recurse -Force `
    -ErrorAction SilentlyContinue

New-Item `
    -ItemType Directory `
    -Path "$Scratch\ISO\sources\" `
    -Force | Out-Null

New-Item `
    -ItemType Directory `
    -Path "$Scratch\MNT" `
    -Force | Out-Null

#===========================================================================================================
# Mount and Extract the Windows 11 ISO

Write-Host "`nMounting Source ISO ..."

$mount = Get-DiskImage -ImagePath $Source

if (-not $mount.Attached) {

    $mount = Mount-DiskImage `
        -ImagePath $Source `
        -PassThru -Verbose

}

$ISOmnt = ($mount | Get-Volume).DriveLetter

# Find Index # for Windows 11 Pro
$WIMindex = ( `
    (Get-WindowsImage -ImagePath "$($ISOmnt):\sources\install.wim") `
    | Where-Object ImageName -eq 'Windows 11 Pro' `
).ImageIndex

Write-Host "`nCopying 'install.wim' ..."

Copy-Item `
    -Path "$($ISOmnt):\sources\install.wim" `
    -Destination "$Scratch\ISO\sources\install.wim"

Write-Host "`nDismounting Source ISO ..."

Get-Volume `
    -DriveLetter $ISOmnt `
    | Get-DiskImage `
    | Dismount-DiskImage `
    | Out-Null

#===========================================================================================================
# Extract the Windows 10 Installer ZIP

Write-Host "`nExtracting 'Win10Setup.zip' ..."

Expand-Archive `
    -Path "bin\Win10Setup.zip" `
    -DestinationPath "$Scratch\ISO" `
    -Force

#===========================================================================================================
# Mount Windows 11 Image

Write-Host "`nMounting 'install.wim' ..."

attrib -r "$Scratch\ISO\sources\install.wim" >$null

Mount-WindowsImage `
    -ImagePath "$Scratch\ISO\sources\install.wim" `
    -Path "$Scratch\MNT\" `
    -Index $WIMindex `
    | Out-Null

#===========================================================================================================
# Remove Packages from the image

Get-Content -Path "bin\Win11Debloat\Appslist.txt" | ForEach-Object {
    
    $app = ($_.Split('#')[0].Trim())

    Write-Output "`nRemoving app: '$app'"
    
    # Remove provisioned app from OS image, so the app won't be installed for any new users
    Get-AppxProvisionedPackage `
        -Path "$Scratch\MNT\" `
    | Where-Object PackageName -like $app `
    | Remove-ProvisionedAppxPackage `
        -Path "$Scratch\MNT\"

}

#===========================================================================================================
# Modify the registry of the image

# Mount Registry
reg load HKLM\zCOMPONENTS "$Scratch\MNT\Windows\System32\config\COMPONENTS" | Out-Null
reg load HKLM\zDEFAULT    "$Scratch\MNT\Windows\System32\config\default"    | Out-Null
reg load HKLM\zNTUSER     "$Scratch\MNT\Users\Default\ntuser.dat"           | Out-Null
reg load HKLM\zSOFTWARE   "$Scratch\MNT\Windows\System32\config\SOFTWARE"   | Out-Null
reg load HKLM\zSYSTEM     "$Scratch\MNT\Windows\System32\config\SYSTEM"     | Out-Null

# Iter through REG files
Get-ChildItem -Path "bin\Win11Debloat\Regfiles\" | ForEach-Object {

    Write-Host "`nUpdating Registry: '$($_.Name)'"
    
    reg import $_.FullName

}

# Dismount Registry
reg unload HKLM\zCOMPONENTS | Out-Null
reg unload HKLM\zDEFAULT    | Out-Null
reg unload HKLM\zNTUSER     | Out-Null
reg unload HKLM\zSOFTWARE   | Out-Null
reg unload HKLM\zSYSTEM     | Out-Null

#===========================================================================================================
# Dismount the WIM image

Write-Host "`nDismounting 'install.wim' ..."

Dismount-WindowsImage `
    -Path "$Scratch\MNT\" `
    -Save

#===========================================================================================================

Write-Host "`nExporting 'tiny11.iso' ..."

."bin\oscdimg\oscdimg.exe" `
    -m -o -u2 -udfver102 `
    "-bootdata:2#p0,e,b$Scratch\ISO\boot\etfsboot.com#pEF,e,b$Scratch\ISO\efi\microsoft\boot\efisys.bin" `
    "$Scratch\ISO" `
    $Output

#===========================================================================================================
