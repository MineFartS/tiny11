# tiny11

### Build a debloated Windows 11 image

---
## Parameters:

| Name    | Default                                  | Description          |
|---------|------------------------------------------|----------------------|
| Scratch | %tmp%\tiny11                             | Temporary Directory  |
| Out     | C:\Users\%username%\Downloads\tiny11.iso | Output ISO file path |

---
## Instructions:

1. Download the Windows 11 ISO from the [Microsoft website](https://www.microsoft.com/en-us/software-download/windows11#:~:text=Download%20Windows%2011%20Disk%20Image)

2. Start the script :
```powershell
irm https://raw.githubusercontent.com/MineFartS/tiny11/refs/heads/main/tiny11maker.ps1 | iex
``` 

3. Locate the downloaded ISO file when prompted.

4. Sit back and relax :\)
