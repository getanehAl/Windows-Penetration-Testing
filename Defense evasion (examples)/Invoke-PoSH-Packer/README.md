### Invoke-PoSH-Packer.ps1
--------------------------------------
'Invoke-PoSH-Packer' allows to pack and encrypt offensive PowerShell scripts in order to bypass AV solutions such as Windows Defender.

> Features
  - AES encryption and GZip compression (based on 'Xencrypt')
  - AMSI bypass
  - Blocking Event Tracing for Windows (ETW)
  - Disabling PowerShell history logging
  
> Usage
  - Import-Module ./Invoke-PoSH-Packer.ps1
  - Invoke-PoSH-Packer -FileUrl https://URL/script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1  
  Or  
  - Invoke-PoSH-Packer -FilePath C:\path\script-to-pack.ps1 -OutFile C:\path\Packed-script.ps1

> License
  - GNU General Public License v3.0
