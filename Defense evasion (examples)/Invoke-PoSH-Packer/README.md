### Invoke-PoSH-Packer.ps1
--------------------------------------
'Invoke-PoSH-Packer' allows to pack and encrypt offensive PowerShell scripts in order to bypass AV solutions such as Windows Defender.

> Features
  - AES encryption and GZip compression (based on 'Xencrypt')
  - AMSI bypass
  - Blocking Event Tracing for Windows (ETW)
  - Disabling PowerShell history logging
  - Basic sandbox evasion techniques (optional)
    - stop/exit if the PowerShell session is being debugged (detection based on "Test-Path Variable:PSDebugContext")
    - wait for 60 seconds before execution
  
> Usage
1. Example with a PowerShell script stored locally
```
  - Import-Module ./Invoke-PoSH-Packer.ps1
  - Invoke-PoSH-Packer -FilePath C:\path\script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1 
  --- or ---
  - Invoke-PoSH-Packer -FilePath C:\path\script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1 -sandbox
``` 
2. Example with a PowerShell script stored on a remote web server
```
  - Import-Module ./Invoke-PoSH-Packer.ps1
  - Invoke-PoSH-Packer -FileUrl https://URL/script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1  
  --- or ---
  - Invoke-PoSH-Packer -FileUrl https://URL/script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1 -sandbox
```

> License
  - GNU General Public License v3.0
