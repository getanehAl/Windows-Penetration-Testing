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

3. Gaining Access (black-box tests - i.e. no account)
   ➤ LLMNR & NBT-NS poisonning attacks (collect password hashes from the network + Offline password cracking or SMB relay attacks)
   ➤ Default/weak admin credentials for a software installed on a Windows server that will lead to a RCE
      Examples:
      - Web servers (e.g. Tomcat, WebLogic), CMS => Webshell upload
      - Databases (e.g. MSSQL, Oracle, PostgreSQL) => OS command execution
      - Jenkins => OS command execution
   ➤ Windows password spray attacks
   ➤ Anonymous access to data storage spaces (e.g. FTP/TFTP/NFS) + Windows clear-text credentials hardcoded in scripts, logs and configuration files 
   ➤ Unpatched known vulnerability with a public RCE exploit for Windows OS, Web servers, databases, FTP servers…  
      Examples:
      - Windows: CVE-2020-0688, MS17-010, MS08-067 
      - Web servers: Apache Struts RCE (CVE-2017-9805), JBoss RCE (CVE-2017-12149), WebLogic RCE (CVE-2017-10271),... 
      - Citrix NetScaler: CVE-2019-19781
   
4. Gaining Access (grey-box tests i.e. with 1 standard Windows account)
   ➤ Kerberoasting attack (collect Kerberos service tickets for any service with an SPN + Offline password cracking of service accounts)
   ➤ Windows network shares, SYSVOL/GPP, NAS, SharePoint sites, internal github (accessible to any authenticated user) + Windows clear-text credentials hardcoded in scripts, logs and configuration files 
   ➤ Clear-text passwords stored in AD fields (e.g. account description, comments)
   ➤ Citrix servers accessible to any employee + Citrix jailbreak to get a Windows CMD or PowerShell console
   ➤ ...

5. Post-exploitation and privilege escalation to become "Local Administrator" and "Local System"
   ➤ Exploiting OS security misconfiguration 
      Examples:
      - weak service permissions, weak file permissions, weak registry permissions, dll hijacking,
      - weak passwords, password re-use, clear-text passwords stored in scripts, unattended install files, 
      - AlwaysInstallElevated trick
   ➤ Exploiting an unpatched known vulnerability with a public exploit (e.g.  MS16-032, Hot/Rotten/Juicy Potato exploits)
   ➤ Dumping Local Windows credentials (SAM/SYSTEM/SECURITY, LSASS)
     
6. Network lateral movement and "Domain Admin" credentials hunting
   ➤ RDP, WMIexec, Evil WinRM, SMBexec, PsExec..
   ➤ Pivoting techniques (e.g. meterpreter pivoting techniques)
   ➤ Pass-The-Hash & Pass-The-Ticket techniques (e.g. using the built-in local admin account and/or domain accounts member of the "Local Adminstrators" group)
   ➤ Password dumping techniques (ProcDump, Mimikatz, SecretsDump..)
   ➤ Reconnaissance ("Domain Admin" credentials hunting) with BloodHound, PowerShell scripts/commands..

7. Privilege escalation to become "Domain Admin", "Entreprise Admin"
   ➤ The same password is used to protect the built-in local administrator account of the Windows servers and Domain Controllers (i.e. no hardening, no LAPS)
   ➤ Dumping from a Windows server's memory the clear-text password of a high privileged acccount (e.g. Domain Admins, Entreprise Admins, DC BUILTIN\Administrators, ...) 
   ➤ Exploiting AD / Windows domain misconfiguration
      Examples:
      - weak ACLs configuration,  weak GPO permissions,
      - LAPS misconfiguration, password re-use between privileged and standard accounts, ...
   ➤ Compromise an account member of the built-in group "DNSAdmins" or "Account Operators" and then use it to take over the AD
   ➤ Find a backup/snapshot of a Windows Domain Controller on a NAS/FTP/Share and extract the password hashes (NTDS.DIT + SYSTEM) of high privileged acccounts (e.g. Domain Admins, Entreprise Admins, DC BUILTIN\Administrators)
   ➤ Hack the Hypervsior on which the Domain Controllers are running, then peform a snapshot or dump just their memory and finally extract the password hashes of high privileged acccounts (e.g. Domain Admins, Entreprise Admins, DC BUILTIN\Administrators)
   ➤ ...
   
8. Post-exploitation AD
   ➤ Dumping Domain Windows credentials (NTDS.DIT + SYSTEM reg hive)
   ➤ Persistance with the KRBTGT account’s password hash and the creation of a Golden ticket
   ➤ Take over other Windows domains due to password re-use across domains for high privileged accounts
   ➤ Take over the Forest root domain thanks to AD Forest Trusts and/or misconfiguration (e.g. no SID filtering = SID history attack) 
   ➤ ...
```

#### Useful tools and scripts
```
➤ NMAP - Network port scanner and (NSE) scripts (https://nmap.org)
➤ Windows Sysinternals (https://docs.microsoft.com/en-us/sysinternals/)
➤ Windows native DOS cmd and PowerShell commands
➤ ADRecon - Active Directory gathering information tool (https://github.com/adrecon/ADRecon)
➤ BloodHound - Tool to easily identify complex Windows domain attack paths (https://github.com/BloodHoundAD/BloodHound)
➤ ACLight - A tool for advanced discovery of privileged accounts including Shadow Admins (https://github.com/cyberark/ACLight)
➤ Liza - Active Directory Security, Permission and ACL Analysis (http://www.ldapexplorer.com/en/liza.htm)
➤ Responder - LLMNR/NBTNS/mDNS poisoner and NTLMv1/2 relay (https://github.com/lgandx/Responder)
➤ PowerSploit (incl. PowerView & PowerUp) - PowerShell offensive security framework (https://github.com/PowerShellMafia/PowerSploit)
➤ Impacket (incl. SecretDump & WMIexec) - Python offensive security framework (https://github.com/SecureAuthCorp/impacket)
➤ CrackMapExec - Swiss army knife for pentesting Windows networks (https://github.com/byt3bl33d3r/CrackMapExec)
➤ Metasploit penetration testing framework (https://www.metasploit.com)
➤ Rubeus - Toolset for raw Kerberos interaction and abuses (https://github.com/GhostPack/Rubeus)
➤ Mimikatz - Extract plaintexts passwords, hash, PIN code and kerberos tickets from memory (https://github.com/gentilkiwi/mimikatz)
➤ Powercat - PowerShell TCP/IP swiss army knife like netcat (https://github.com/besimorhino/powercat)
➤ LAPSToolkit - LAPS auditing for pentesters (https://github.com/leoloobeek/LAPSToolkit)
➤ Juicy potato exploit (https://github.com/ohpe/juicy-potato)
➤ Rotten potato  exploit (https://github.com/breenmachine/RottenPotatoNG)
➤ PingCastle - Active Directory security audit tool (https://www.pingcastle.com)
➤ Hydra - Online password bruteforce tool (https://github.com/vanhauser-thc/thc-hydra)
➤ John the Ripper - Offline password cracker (https://www.openwall.com/john/)
➤ Hashcat - Offline password cracker (https://hashcat.net/hashcat/)
➤ Enum4linux - Tool for enumerating information from Windows and Samba systems (https://tools.kali.org/information-gathering/enum4linux)
➤ Vulnerability scanners (e.g. OpenVAS, Nessus, Qualys, Nexpose, ...)
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
