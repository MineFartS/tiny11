
param(
    $Scratch = "$env:TEMP\tiny11",
    $Out = "$env:USERPROFILE\Downloads\tiny11.iso",
    $Source
)

#===========================================================================================================
# Force Elevation

# Check and run the script as admin if required
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
# Prepare the Terminal

# Set the window title
$Host.UI.RawUI.WindowTitle = "Tiny11 Image Creator"

Clear-Host

#===========================================================================================================
# Prompt for the Windows 11 Installer ISO

if ($null -eq $Source) {

    Add-Type -AssemblyName System.Windows.Forms
    $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $fileDialog.InitialDirectory = "$env:USERPROFILE\Downloads"
    $fileDialog.Filter = 'ISO Files (*.iso)|*.iso|All Files (*.*)|*.*'
    $fileDialog.Title = 'Please select an ISO file to mount'
    $fileDialog.ShowHelp = $true
    $fileDialog.ShowDialog() | Out-Null

    $Source = $fileDialog.FileName

}

#===========================================================================================================
# Create Scratch Directories

takeown.exe /f $Scratch /r /d Y
icacls.exe $Scratch /t /c /grant Administrators:F

Remove-Item `
    -Path "$Scratch\ISO\" `
    -Verbose -Recurse -Force

Remove-Item `
    -Path "$Scratch\MNT\" `
    -Verbose -Recurse -Force

Remove-Item `
    -Path "$Scratch\Win11Debloat-master\" `
    -Verbose -Recurse -Force

New-Item `
    -ItemType Directory `
    -Force `
    -Path "$Scratch\ISO\sources\" `
    | Out-Null

New-Item `
    -ItemType Directory `
    -Force `
    -Path "$Scratch\MNT" `
    | Out-Null

#===========================================================================================================
# Mount and Extract the Windows 11 ISO

# Mount the ISO and get the assigned drive letter
$mountResult = Mount-DiskImage `
    -ImagePath $Source `
    -PassThru

#
$ISOmnt = ($mountResult | Get-Volume).DriveLetter

# Find Index # for Windows 11 Pro
$index = ( `
    (Get-WindowsImage -ImagePath "$($ISOmnt):\sources\install.wim") `
    | Where-Object ImageName -eq 'Windows 11 Pro' `
).ImageIndex

Write-Host "Exporting image ..."
Dism.exe `
    /Export-Image `
    "/SourceImageFile:$($ISOmnt):\sources\install.wim" `
    "/SourceIndex:$index" `
    "/DestinationImageFile:$Scratch\ISO\sources\install.wim" `
    "/Compress:recovery"

# Unmount the ISO
Get-Volume `
    -DriveLetter $ISOmnt `
    | Get-DiskImage `
    | Dismount-DiskImage

#===========================================================================================================
# Download & Extract the Windows 10 Installer ZIP

if (-not (Test-Path "$Scratch\Win10Setup.zip")) {

    Invoke-WebRequest `
        -Uri "https://github.com/MineFartS/tiny11/raw/refs/heads/main/Win10Setup.zip" `
        -OutFile "$Scratch\Win10Setup.zip"

}

Expand-Archive `
    -Path "$Scratch\Win10Setup.zip" `
    -DestinationPath "$Scratch\ISO" `
    -Force -Verbose

#===========================================================================================================
# Download & Extract Win11Debloat

if (-not (Test-Path "$Scratch\win11debloat.zip")) {

    Invoke-RestMethod `
        -Uri 'https://github.com/MineFartS/Win11Debloat/archive/refs/heads/master.zip' `
        -OutFile "$Scratch\win11debloat.zip"

}

Expand-Archive `
    -Path "$Scratch\win11debloat.zip" `
    -DestinationPath $Scratch `
    -Verbose -Force

#===========================================================================================================
# Mount Windows 11 Image

takeown.exe /f "$Scratch\ISO\sources\install.wim" /r /d Y
icacls.exe "$Scratch\ISO\sources\install.wim" /t /c /grant Administrators:F

Mount-WindowsImage `
    -ImagePath "$Scratch\ISO\sources\install.wim" `
    -Path "$Scratch\MNT\" `
    -Index 1

#===========================================================================================================
# Remove Packages from the image

Get-Content -Path "$Scratch\Win11Debloat-master\Appslist.txt" | ForEach-Object {
    
    #
    $app = ($_.Split('#')[0].Trim())

    Write-Host ""
    Write-Output "Removing app: '$app'"

    #
    if (($app -eq "Microsoft.OneDrive") -or ($app -eq "Microsoft.Edge")) {

        winget.exe `
            uninstall `
            --accept-source-agreements `
            --id $app

    #
    } else {
            
        Get-AppxPackage `
            -Name "*$app*" `
            -AllUsers `
        | Remove-AppxPackage `
            -AllUsers `
            -ErrorAction Continue

    }

    # Remove provisioned app from OS image, so the app won't be installed for any new users
    Get-AppxProvisionedPackage -Online `
    | Where-Object PackageName -like $app `
    | ForEach-Object { 
        Remove-ProvisionedAppxPackage `
        -Online -AllUsers `
        -PackageName $_.PackageName 
    }

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
Get-ChildItem -Path "$Scratch\Win11Debloat-master\Regfiles\" | ForEach-Object {

    Write-Host "Updating Registry: '$($_.Name)'"
    
    reg import $_.FullName

}

# Dismount Registry
reg unload HKLM\zCOMPONENTS | Out-Null
reg unload HKLM\zDEFAULT    | Out-Null
reg unload HKLM\zNTUSER     | Out-Null
reg unload HKLM\zSOFTWARE   | Out-Null
reg unload HKLM\zSYSTEM     | Out-Null

#===========================================================================================================

#
Dismount-WindowsImage `
    -Path "$Scratch\MNT\" `
    -Save

#===========================================================================================================
# Cleanup the image

dism.exe `
    "/Image:$Scratch\ISO\" `
    /Cleanup-Image `
    /StartComponentCleanup `
    /ResetBase

#===========================================================================================================
# Export the image

Invoke-WebRequest `
    -Uri "https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe" `
    -OutFile "$Scratch\oscdimg.exe"

."$Scratch\oscdimg.exe" `
    -m -o -u2 -udfver102 `
    "-bootdata:2#p0,e,b$Scratch\ISO\boot\etfsboot.com#pEF,e,b$Scratch\ISO\efi\microsoft\boot\efisys.bin" `
    "$Scratch\ISO" `
    $Out

#===========================================================================================================
# Finalize

Write-Output "Creation completed!"

Pause
