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
  - Compatible with shellcodes of multiple C2 frameworks such as: Metasploit, Silver and Havoc
    
#### TESTS
- Succesfully tested on a Windows 10 x64 laptop (target) with Windows Defender enabled (without 'Automatic sample submission') and shellcodes of multiple C2 frameworks (in C# format & encrypted with XOR cipher algorithm)

#### COMPILATION GUIDELINES
- Code compiled with "Developer PowerShell for VS 2022"
  - Microsoft (R) Visual C# Compiler version 4.5.0-6.23123.11
  - Command: csc /t:exe /out:C:\path\Loader.exe C:\path\CsharpShellCodeLoader.cs
- The file 'CsharpShellCodeLoader.cs' is voluntary not obfuscated. Class/function/variable names should be changed and all comments must be deleted or modified before compiling this file.
- Your shellcode must be in C# format and then encrypted using XOR cipher. Obviously, the XOR key must be replaced in the file with the one you used.
- Once compiled, if you want to compress and obfuscate the shellcodeloader executable you can use packers like "Confuser-Ex" but it is not mandatory to bypass most AV solutions. 
  
