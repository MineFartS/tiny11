<h1> tiny11
<h2>Script to build a debloated Windows 11 image</h2>

---
## Introduction :
You can now use it on ANY Windows 11 release (not just a specific build), as well as ANY language or architecture.

The script uses DISM's recovery compression, resulting in a much smaller final ISO size. The only other executable included is **oscdimg.exe**, which is provided in the Windows ADK and it is used to create bootable ISO images. 
Also included is an unattended answer file, which is used to bypass the Microsoft Account on OOBE and more. You can see all the configuration <a href="https://schneegans.de/windows/unattend-generator/?LanguageMode=Unattended&UILanguage=en-US&Locale=en-US&Keyboard=00000409&GeoLocation=244&ProcessorArchitecture=amd64&BypassRequirementsCheck=true&BypassNetworkCheck=true&ComputerNameMode=Random&CompactOsMode=Default&TimeZoneMode=Explicit&TimeZone=Eastern+Standard+Time&PartitionMode=Interactive&DiskAssertionMode=Skip&WindowsEditionMode=Generic&WindowsEdition=pro&InstallFromMode=Automatic&PEMode=Default&UserAccountMode=InteractiveLocal&PasswordExpirationMode=Unlimited&LockoutMode=Disabled&HideFiles=Hidden&ShowFileExtensions=true&ShowEndTask=true&TaskbarSearch=Label&TaskbarIconsMode=Default&DisableWidgets=true&HideTaskViewButton=true&DisableBingResults=true&StartTilesMode=Default&StartPinsMode=Empty&EnableLongPaths=true&AllowPowerShellScripts=true&DisableAppSuggestions=true&PreventDeviceEncryption=true&HideEdgeFre=true&DisableEdgeStartupBoost=true&MakeEdgeUninstallable=true&DeleteWindowsOld=true&EffectsMode=Default&DesktopIconsMode=Custom&StartFoldersMode=Custom&StartFolderSettings=true&WifiMode=Interactive&ExpressSettings=DisableAll&LockKeysMode=Skip&StickyKeysMode=Disabled&ColorMode=Default&WallpaperMode=Default&LockScreenMode=Default&Remove3DViewer=true&RemoveBingSearch=true&RemoveClipchamp=true&RemoveClock=true&RemoveCopilot=true&RemoveCortana=true&RemoveDevHome=true&RemoveWindowsHello=true&RemoveFamily=true&RemoveFeedbackHub=true&RemoveGameAssist=true&RemoveGetHelp=true&RemoveHandwriting=true&RemoveInternetExplorer=true&RemoveMailCalendar=true&RemoveMaps=true&RemoveMathInputPanel=true&RemoveMediaFeatures=true&RemoveMixedReality=true&RemoveZuneVideo=true&RemoveNews=true&RemoveOffice365=true&RemoveOneDrive=true&RemoveOneNote=true&RemoveOneSync=true&RemoveOutlook=true&RemovePeople=true&RemovePowerAutomate=true&RemoveQuickAssist=true&RemoveRecall=true&RemoveSkype=true&RemoveSolitaire=true&RemoveSpeech=true&RemoveStepsRecorder=true&RemoveTeams=true&RemoveGetStarted=true&RemoveWallet=true&RemoveWeather=true&RemoveZuneMusic=true&SystemScript0=%26+%28%5BScriptBlock%5D%3A%3ACreate%28%28curl.exe+-s+--doh-url+https%3A%2F%2F1.1.1.1%2Fdns-query+https%3A%2F%2Fget.activated.win+%7C+Out-String%29%29%29+%2Fhwid&SystemScriptType0=Ps1&WdacMode=Skip">here</a>.

---
## Instructions:
1. Download Windows 11 from the [Microsoft website](https://www.microsoft.com/software-download/windows11)
2. Mount the downloaded ISO image using Windows Explorer.
3. Open PowerShell as Administrator. 
4. Start the script :
```powershell
irm https://raw.githubusercontent.com/MineFartS/tiny11/refs/heads/main/tiny11maker.ps1 | iex
``` 
5. Follow the instructions given.
7. Sit back and relax :)
8. When the image is completed, you will see it in the folder where the script was extracted, with the name tiny11.iso
