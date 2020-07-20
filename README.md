# Windows Active Directory penetration testing
Technical notes and list of tools, scripts and Windows commands that I find useful during internal penetration tests (Windows environment/Active Directory).

The output files included here are the results of tools, scripts and Windows commands that I ran against a vulnerable Windows AD lab that I created to deliver hands-on penetration testing training sessions to security auditors at my job. In addition to the misconfiguration and security flaws that I created on purpose, I used the awesome tools "BadBlood" and "lpeworkshop" to create my vulnerable Windows lab (thank you guys!).


### Internal penetration test - Classic Windows Active Directory attack paths
```
1. Bypassing Network Access Control (NAC) - if any 
   ➤ Bypass MAC address filtering solution by using the MAC address of a whitelisted device (e.g. a printer, smart TV in meeting room)
   ➤ Hack the captive portal authentication used to control network access
   ➤ ...
   
2. Reconnaissance 
   ➤ AD and Windows domain information gathering (very limited in black-box pentest)
   ➤ Targeted network scans

3. Gaining Access (black-box)
   ➤ LLMNR & NBT-NS poisonning attacks (collect password hashes from other systems on the network + offline password cracking or relay attack)
   ➤ Password spraying attacks
   ➤ Unpatched known (remote) vulnerability with a public exploit available (e.g. CVE-2020-0688, MS17_010, MS14_068)
   ➤ Anonymous access to data storage spaces containing scripts and/or configuration files with clear-text passwords hardcoded (e.g. ftp, tftp, NAS, internal github)
     
4. Gaining Access (grey-box)
   ➤ Kerberoasting attack (collect Kerberos service tickets for any service + offline password cracking of service accounts)
   ➤ Windows network shares, SYSVOL/GPP, NAS, SharePoint sites, internal github (accessible to any authenticated user) containing scripts and/or configuration files with clear-text passwords hardcoded
   ➤ Clear-text passwords stored in AD fields (e.g. account description, comments)
     
5. Post-exploitation and privilege escalation to become "Local Administrator" and "Local System"
   ➤ Security misconfiguration (e.g. weak service permissions, weak file permissions, weak registry permissions, weak passwords, password reuse, clear-text passwords stored in scripts, unattended install files, AlwaysInstallElevated trick..)
   ➤ Unpatched known vulnerability with a public exploit available (e.g. Hot/Rotten/Juicy Potato exploits, MS16-032)
   ➤ Dumping Local Windows credentials (SAM/SYSTEM/SECURITY, LSASS)
     
6. Network lateral movement and "Domain Admin" credentials hunting
   ➤ WMIexec, Evil WinRM, RDP, SMBexec, PsExec..
   ➤ Reconnaissance with BloodHound, PowerShell scripts/commands..
   ➤ Pass-The-Hash & Pass-The-Ticket techniques (e.g. using the built-in local admin account and/or domain accounts member of the "Local Adminstrators" group)
   ➤ Password dumping techniques (ProcDump, Mimikatz, SecretDump..)
   ➤ Pivoting techniques (e.g. meterpreter pivoting techniques)
     
7. Privilege escalation AD 
   ➤ The same password is used to protect the built-in local administrator account of the Windows servers and Domain Controllers (i.e. no hardening, no LAPS or CyberArk)
   ➤ Dumping from a Windows server's memory the clear-text password of a higly privilged acccount (e.g. Domain Admins, Entreprise Admins, DC BUILTIN\Administrators),.. 
   ➤ AD / Windows domain misconfiguration (e.g. weak ACLs configuration, LAPS misconfiguration, weak passwords, password re-use between privileged and standard accounts, weak GPO permissions, ...)
     
8. Post-exploitation AD
   ➤ Dumping Domain Windows credentials (NTDS.DIT)
   ➤ Persistance with the KRBTGT account’s password hash and the creation of Golden tickets 
   ➤ Take over other Windows domains due to password re-use across domains for higly privileged accounts
   ➤ Take over the Forest root domain thanks to AD Forest Trusts and/or misconfiguration (e.g. no SID filtering = SID history attack) 
```

#### Useful tools and scripts
```
➤ NMAP - Network port scanner and (NSE) scripts (https://nmap.org)
➤ Windows Sysinternals (https://docs.microsoft.com/en-us/sysinternals/)
➤ Windows native DOS cmd and PowerShell commands
➤ ADRecon - Active Directory gathering information tool (https://github.com/adrecon/ADRecon)
➤ BloodHound - Tool to easily identify complex Windows domain attack paths (https://github.com/BloodHoundAD/BloodHound)
➤ ACLight - A tool for advanced discovery of privileged accounts including Shadow Admins (https://github.com/cyberark/ACLight)
➤ Responder - LLMNR/NBTNS/mDNS poisoner and NTLMv1/2 relay (https://github.com/lgandx/Responder)
➤ PowerSploit (incl. PowerView & PowerUp) - PowerShell offensive security framework (https://github.com/PowerShellMafia/PowerSploit)
➤ Impacket (incl. SecretDump & WMIexec) - Python offensive security framework (https://github.com/SecureAuthCorp/impacket)
➤ CrackMapExec - Swiss army knife for pentesting Windows networks (https://github.com/byt3bl33d3r/CrackMapExec)
➤ Metasploit penetration testing framework (https://www.metasploit.com)
➤ Rubeus - Toolset for raw Kerberos interaction and abuses (https://github.com/GhostPack/Rubeus)
➤ Mimikatz - Dump clear-text credentials from Windows memory (https://github.com/gentilkiwi/mimikatz)
➤ Powercat - PowerShell TCP/IP swiss army knife like netcat (https://github.com/besimorhino/powercat)
➤ LAPSToolkit - LAPS auditing for pentesters (https://github.com/leoloobeek/LAPSToolkit)
➤ PingCastle - Active Directory security audit tool (https://www.pingcastle.com)
➤ Hydra - Online password bruteforce tool (https://github.com/vanhauser-thc/thc-hydra)
➤ John the Ripper - Offline password cracker (https://www.openwall.com/john/)
➤ Hashcat - Offline password cracker (https://hashcat.net/hashcat/)
➤ Enum4linux - Tool for enumerating information from Windows and Samba systems (https://tools.kali.org/information-gathering/enum4linux)
➤ Vulnerability scanners (e.g. OpenVAS, Nessus, Qualys, ...)
➤ Various scripts (source:kali/Github/your owns)
```

#### Useful resources
```
➤ ADsecurity website (https://adsecurity.org)
➤ GitHub - swisskyrepo/PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
➤ MITRE (https://attack.mitre.org/mitigations/M1015/)
➤ Att&cking Active Directory for fun and profit (https://identityaccessdotmanagement.files.wordpress.com/2020/01/attcking-ad-for-fun-and-profit.pdf)
➤ Windows / Linux Local Privilege Escalation Workshop (https://github.com/sagishahar/lpeworkshop)
➤ ...
```
