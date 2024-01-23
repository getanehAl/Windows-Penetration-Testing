### C# ShellCode Loader
--------------------------------------
I shamellesly took and assembled codes from Github to have a quick and dirty C# shellcode laoder (in 1 .CS file) that implements the following defense evasion techniques:
  - NTDLL unhooking (it loads a fresh new copy of the ntdll.dll via file mapping and imports functions from this ntdll.dll)
  - Shellcode encryption (XOR)
  - AMSI bypass
  - Basic sandbox detection/evasion techniques
    - Exit if the the program is running on a computer that is not joined to a domain
    - Exit if after sleeping for 15s, time did not really passed
    - Exit if a debugger is attached
    - Exit if making an uncommon API call fails (meaning the AV sandbox can't emulating it)
 
<i/>Additional information</i>
- Code compiled with "Developer PowerShell for VS 2022"
  - Microsoft (R) Visual C# Compiler version 4.5.0-6.23123.11
  - Command: csc /t:exe /out:C:\temp\CsharpShellCodeLoader\Loader.exe C:\temp\CsharpShellCodeLoader\Program.cs
- Succesfully tested on a Windows 10 x64 laptop (target) with Windows Defender (without 'Automatic sample submission') and a shellcode generated with the Havoc C2 (in C# format & encrypted with XOR cipher algorithm)  
