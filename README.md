## Windows Active Directory penetration testing
Technical notes and list of tools, scripts and Windows commands that I find useful during internal penetration tests (Windows environment/Active Directory).

The output files included here are the results of tools, scripts and Windows commands that I ran against a vulnerable Windows AD lab that I created to deliver hands-on penetration testing training sessions to security auditors at my job. In addition to the misconfiguration and security flaws that I created on purpose, I used the awesome tools "BadBlood" and "lpeworkshop" to create my vulnerable Windows lab (thank you guys!).


### Internal penetration test - Classic Windows Active Directory attack paths

#### Step 1. Bypassing Network Access Control (NAC) - if any
```
➤ Bypass MAC address filtering solution by using/spoofing the MAC address of a whitelisted device (e.g. a printer, smart TV in meeting room)
➤ Hack the captive portal authentication used to control network access
➤ ...
```

#### Step 2. Reconnaissance and Scanning
```
Black-box penetration test (we start with no account)
-----------------------------------------------------
➤ On our laptop connected to the LAN or Wifi, we run commands like 'ipconfig /all' and 'nslookup' to identify:
 - the IP address range of the user network (our laptop IP address is part of it)
 - the IP address range of a production (server) network (thanks to the IP address of the DNS server which is usually also the IP address of a Domain Controller) 
➤ Reconnaissance using DNS queries (e.g. reverse IP lookup, DNS zone transfer) and the naming convention of the hostnames
  Examples:
  - Domain Controllers have often a hostname like 'pr<bla>dc1', 'dv<bla>ad2', 'usdc02', 'prodfrdc3', etc.
  - Web servers have often a hostname like 'prweb01', 'wwwserver02', 'win2k16iis03', 'devJBOSS04', etc.
  - Database servers have often a hostname like 'sqlsrv01', 'prdbserver02', 'prodorasrv08', 'devmongodb14', etc. 
  - Citrix servers have often a hostname like 'prctxsrv1', 'printctx02', 'citrixsrv02', etc.
➤ Targeted network scans (e.g. Nmap and NSE scripts)
➤ Network sniffing

Grey-box penetration test (we start with 1 low-privileged Windows account)
--------------------------------------------------------------------------
➤ AD and Windows domain information gathering 
  - When we have at least 1 Windows account, there are numerous tools and scripts that can be used to enumerate a Windows domain
    Examples:
    + Windows native DOS and Powershell commands (e.g. 'net' commands, PowerShell ActiveDirectory module)
    + Sysinternals tools (e.g. ADexplorer.exe)
    + Powershell scripts like ADrecon.ps1
    + BloodHound 
    + PingCastle
    + ADCollector
    + PowerView framework / SharpView
```

#### Step 3. Gaining Access 
```
Black-box penetration test (we start with no account)
-----------------------------------------------------
➤ LLMNR & NBT-NS poisonning attacks using the tool Responder (poison name services + collect NTLMv2 password hashes from the network + offline password cracking or SMB relay attacks)
➤ DNS poisoning attacks via IPv6 DHCP requests using the tool MITM6 (spoof DNS replies + collect NTLMv2 password hashes from the network + offline password cracking or SMB relay attacks)    
➤ Default/weak admin credentials for a software installed on a Windows server that will lead to a RCE
  Examples:
  - Web servers (e.g. Tomcat, WebLogic), CMS => Webshell upload
  - Databases (e.g. MSSQL, Oracle, PostgreSQL) => OS command execution
  - Jenkins => OS command execution
➤ Windows password spray attacks
➤ Anonymous access to data storage spaces (e.g. FTP/TFTP/NFS) + Windows clear-text credentials hardcoded in scripts, logs and configuration files 
➤ Upload of malicious SCF files to anonymously writable Windows network shares + collect NTLMv2 password hashes + offline password cracking
➤ Unpatched unauthenticated Remote Code Execution vulnerability with a public exploit for Windows OS, Web servers, databases, FTP servers…  
  Examples:
  - Windows: PetitPotam vulnerability, CVE-2020-1472 (zerologon - not recommended), MS17-010 (EternalBlue), MS08-067, ... 
  - Web servers: WebLogic RCE (CVE-2020-14882, CVE-2017-10271), Apache Struts RCE (CVE-2017-9805), JBoss RCE (CVE-2017-12149), Java RMI RCE, ...
  - CMS: Telerik (CVE 2019-18935, CVE-2017-9248), Drupal (DrupalGeddon2/CVE-2018-7600), DotNetNuke (CVE-2017-9822), ...
  - Citrix NetScaler: CVE-2019-19781
  
Grey-box penetration test (we start with 1 low-privileged Windows account)
--------------------------------------------------------------------------
➤ All the attacks listed above in the 'black-box pentest' section
➤ Kerberoasting attack (collect Kerberos service tickets for any service with an SPN + offline service account credential hashes cracking)
➤ ASREPRoast attack (retrieve crackable hashes from KRB5 AS-REP responses for users without kerberoast pre-authentication enabled + offline password cracking)
➤ Windows network shares, SYSVOL/GPP, NAS, SharePoint sites, internal github (accessible to any authenticated user) + Windows clear-text credentials hardcoded in scripts, logs and configuration files 
➤ Upload of malicious SCF files to Windows network shares (writable for any authenticated users) + collect NTLMv2 password hashes + offline password cracking
➤ Clear-text passwords stored in AD fields (e.g. account description, comments)
➤ Citrix servers accessible to any employee + Citrix jailbreak to get a Windows CMD or PowerShell console
➤ Unpatched authenticated Remote Code Execution vulnerability with a public exploit for Windows OS, Web servers, databases, FTP servers…  
  Examples:
  - Windows: PrintNightmare (CVE-2021-1675 & CVE-2021-34527), MS14-068
  - Outlook server: CVE-2020-0688
  ➤ ...
```

#### Step 4. Post-exploitation and privilege escalation to become "Local Administrator" and/or "Local System"
```
➤ Exploiting OS security misconfiguration 
  Examples:
  - weak service permissions, weak file permissions, weak registry permissions, dll hijacking,
  - weak passwords, password re-use, clear-text passwords stored in scripts, unattended install files, 
  - AlwaysInstallElevated trick
 ➤ Exploiting an unpatched local privesc vulnerability with a public exploit (e.g. PrintNightmare, HiveNightmare, CVE-2020-0787, Juicy/Rotten/Hot Potato exploits, MS16-032)
 ➤ Dumping Windows credentials (SAM/SYSTEM/SECURITY, LSASS) - Password dumping techniques: ProcDump, Mimikatz, SecretsDump, Reg save, VSS shadow copy, ...
```

#### Step 5. Network lateral movement and 'Domain Admin' credentials hunting
```
➤ Network lateral movement using RDP, WMIexec, PowerShell remoting, Evil WinRM, SMBexec, PsExec..
➤ Pass-The-Hash, Pass-The-Ticket and Over-Pass-The-Hash techniques 
➤ Pivoting techniques
  Examples:
  - Meterpreter with 'post/multi/manage/autoroute' + socks proxy + use of proxychains
  - SSH tunnelling (dynamic port forwarding, local port forwarding, remote port forwarding)
➤ 'Domain Admin' credentials hunting
  Examples:
  - BloodHound
  - PowerView and various PowerShell scripts
  - Windows native commands such as 'qwinsta /server:hostname'
  - ...
```
#### Step 6. Privilege escalation to become "Domain Admin"
```
➤ The same password is used to protect the local administrator account of the Windows servers and the Domain Controllers (i.e. no hardening, no LAPS)
➤ Dumping from a Windows server's memory the clear-text password (or hash) of a high privileged acccount (e.g. Domain Admins, Administrators of DC, ...) 
➤ Exploiting AD / Windows domain misconfiguration
  Examples:
  - weak ACL or GPO permissions, 
  - LAPS misconfiguration, 
  - password re-use between privileged and standard accounts, 
➤ Compromise an account member of the default security group 'DNSAdmins' or 'Account Operators' and then use it to take over the AD (privesc)
➤ Find a backup/snapshot of a Windows Domain Controller on a NAS/FTP/Share and extract the password hashes (NTDS.DIT + SYSTEM) of high privileged acccounts (e.g. Domain Admins, Enterprise Admins, krbtgt account)
➤ Hack the Hypervisor (e.g. vCenter) on which the Domain Controllers are running, then perform a snapshot of the DCs, copy/download their memory dump files (.vmsn & .vmem) and finally extract the password hashes of high privileged acccounts (e.g. Domain Admins, Enterprise Admins, DC BUILTIN\Administrators, krbtgt account)
➤ Kerberos Unconstrained Delegation attack (+ Printer Bug)
➤ Kerberos Constrained Delegation attack
➤ Kerberos Resource-based Constrained Delegation attack
➤ ...
```

#### Step 7. Post-exploitation AD - Persistence and Forest root domain compromise
```
➤ Dump, extract and crack the password hashes of all the Windows domain accounts (file 'NTDS.DIT' + SYSTEM registry hive)
➤ Persistence with the KRBTGT account’s password hash and the creation of a Kerberos Golden ticket
➤ Persistence by modifying ACLs or by setting a Kerberos Resource-Based Constrained Delegation (RBCD)
➤ Take over the Forest root domain
  - Forge a Kerberos Golden Ticket (TGT) with a 'SID History' for the Forest Enterprise Admins group
  - Forge an inter-realm trust ticket (cross-domain trust kerberos ticket) and then create TGS for the services LDAP/CIFS/HOST/... in the parent domain 
➤ Take over other Windows domains due to password re-use across domains for high privileged accounts
➤ Take over other Windows domains thanks to AD Forest Trusts and/or misconfiguration (e.g. the group 'Domain Admins' of the domain A is member of the group 'Domain Admins' of the domain B) 
➤ ...
```

#### Useful tools and scripts
```
➤ NMAP - Network port scanner and (NSE) scripts (https://nmap.org)
➤ Windows Sysinternals (https://docs.microsoft.com/en-us/sysinternals/)
➤ Windows native DOS cmd and PowerShell commands
➤ ADRecon - Active Directory gathering information tool (https://github.com/adrecon/ADRecon)
➤ PingCastle - Active Directory security audit tool (https://www.pingcastle.com)
➤ BloodHound - Tool to easily identify complex Windows domain attack paths (https://github.com/BloodHoundAD/BloodHound)
➤ ACLight - A tool for advanced discovery of privileged accounts including Shadow Admins (https://github.com/cyberark/ACLight)
➤ Liza - Active Directory Security, Permission and ACL Analysis (http://www.ldapexplorer.com/en/liza.htm)
➤ Responder - LLMNR/NBTNS/mDNS poisoner and NTLMv1/2 relay (https://github.com/lgandx/Responder)
➤ PowerSploit (incl. PowerView & PowerUp) - PowerShell offensive security framework (https://github.com/PowerShellMafia/PowerSploit)
➤ Impacket (incl. Secretsdump & WMIexec) - Python offensive security framework (https://github.com/SecureAuthCorp/impacket)
➤ CrackMapExec - Swiss army knife for pentesting Windows networks (https://github.com/byt3bl33d3r/CrackMapExec)
➤ Metasploit penetration testing framework (https://www.metasploit.com)
➤ Rubeus - Toolset for raw Kerberos interaction and abuses (https://github.com/GhostPack/Rubeus)
➤ Mimikatz - Extract plaintexts passwords, hash, PIN code and kerberos tickets from memory (https://github.com/gentilkiwi/mimikatz)
➤ Powercat - PowerShell TCP/IP swiss army knife like netcat (https://github.com/besimorhino/powercat)
➤ LAPSToolkit - LAPS auditing for pentesters (https://github.com/leoloobeek/LAPSToolkit)
➤ Juicy potato exploit (https://github.com/ohpe/juicy-potato)
➤ Rotten potato exploit (https://github.com/breenmachine/RottenPotatoNG)
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
