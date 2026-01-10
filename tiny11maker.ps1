
param(
    $Scratch = "$env:TEMP\tiny11",
    $Out = "$env:USERPROFILE\Downloads\tiny11.iso"
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

#===========================================================================================================
# Prepare the Terminal

# Set the window title
$Host.UI.RawUI.WindowTitle = "Tiny11 Image Creator"

Clear-Host

#===========================================================================================================
# Prompt for the Windows 11 Installer ISO

Add-Type -AssemblyName System.Windows.Forms
$fileDialog = New-Object System.Windows.Forms.OpenFileDialog
$fileDialog.InitialDirectory = "$env:USERPROFILE\Downloads"
$fileDialog.Filter = 'ISO Files (*.iso)|*.iso|All Files (*.*)|*.*'
$fileDialog.Title = 'Please select an ISO file to mount'
$fileDialog.ShowHelp = $true
$fileDialog.ShowDialog() | Out-Null

#===========================================================================================================
# Create Scratch Directories

Repair-Permissions $Scratch

Remove-Item `
    -Path $Scratch `
    -Verbose -Recurse -Force

New-Item `
    -ItemType Directory `
    -Force `
    -Path "$Scratch\ISO" `
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
    -ImagePath $fileDialog.FileName `
    -PassThru

#
$ISOmnt = ($mountResult | Get-Volume).DriveLetter

# Copy Windows 11 Install Image
Copy-Item `
    -Path $ISOmnt':\sources\install.wim' `
    -Destination "$Scratch\ISO\sources\install.wim" `
    -Force -Verbose

# Unmount the ISO
Get-Volume `
    -DriveLetter $ISOmnt `
    | Get-DiskImage `
    | Dismount-DiskImage

#===========================================================================================================
# Download & Extract the Windows 10 Installer ZIP
    
Invoke-WebRequest `
    -Uri "https://github.com/MineFartS/tiny11/raw/refs/heads/master/Win10Setup.zip" `
    -OutFile "$Scratch\Win10Setup.zip"

Expand-Archive `
    -Path "$Scratch\Win10Setup.zip" `
    -DestinationPath "$Scratch\ISO" `
    -Force -Verbose

#===========================================================================================================
# Download & Extract Win11Debloat

Invoke-RestMethod `
    -Uri 'https://github.com/MineFartS/Win11Debloat/archive/refs/heads/master.zip' `
    -OutFile "$Scratch/win11debloat.zip"

Expand-Archive `
    "$Scratch/win11debloat.zip" `
    "$Scratch/Win11Debloat" `
    -Verbose -Force

#===========================================================================================================
# Mount Windows 11 Image

#
Repair-Permissions "$Scratch\ISO\sources\install.wim"

# Find Index # for Windows 11 Pro
$index = ( `
    (Get-WindowsImage -ImagePath "$Scratch\ISO\sources\install.wim") `
    | Where-Object ImageName -eq 'Windows 11 Pro' `
).ImageIndex

#
Mount-WindowsImage `
    -ImagePath "$Scratch\ISO\sources\install.wim" `
    -Index $index `
    -Path "$Scratch\MNT"

#===========================================================================================================
# Remove Packages from the image

Get-Content -Path "$Scratch\Win11Debloat\Appslist.txt" | ForEach-Object {
    
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
reg load HKLM\zDEFAULT "$Scratch\MNT\Windows\System32\config\default" | Out-Null
reg load HKLM\zNTUSER "$Scratch\MNT\Users\Default\ntuser.dat" | Out-Null
reg load HKLM\zSOFTWARE "$Scratch\MNT\Windows\System32\config\SOFTWARE" | Out-Null
reg load HKLM\zSYSTEM "$Scratch\MNT\Windows\System32\config\SYSTEM" | Out-Null

# Iter through REG files
Get-ChildItem -Path "$Scratch\Win11Debloat\Regfiles\" | ForEach-Object {

    Write-Host "Updating Registry: '$($_.Name)'"
    
    reg import $_.FullName

}

# Dismount Registry
reg unload HKLM\zCOMPONENTS | Out-Null
reg unload HKLM\zDEFAULT | Out-Null
reg unload HKLM\zNTUSER | Out-Null
reg unload HKLM\zSOFTWARE | Out-Null
reg unload HKLM\zSYSTEM | Out-Null

#===========================================================================================================
# Finalize & Export the image

Write-Output "Cleaning up image ..."
dism.exe `
    "/Image:$Scratch\MNT" `
    /Cleanup-Image `
    /StartComponentCleanup `
    /ResetBase

#
Dismount-WindowsImage `
    -Path "$Scratch\MNT" `
    -Save

Write-Host "Exporting image ..."
Dism.exe `
    /Export-Image `
    "/SourceImageFile:$Scratch\ISO\sources\install.wim" `
    "/SourceIndex:$index" `
    "/DestinationImageFile:$Scratch\ISO\sources\install2.wim" `
    "/Compress:recovery"

Remove-Item `
    -Path "$Scratch\ISO\sources\install.wim" `
    -Force | Out-Null

Rename-Item `
    -Path "$Scratch\ISO\sources\install2.wim" `
    -NewName "install.wim" `
    | Out-Null

#===========================================================================================================
# Finalize

# Finishing up
Write-Output "Performing Cleanup ..."
Remove-Item `
    -Path $Scratch `
    -Recurse -Force | Out-Null

Write-Output "Creation completed!"
Pause