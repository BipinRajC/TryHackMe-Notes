##### Exploiting Samba Shares

- `nmap -sC -sV -Pn 10.10.82.245 --vv` - gives 7 open ports 
- script to enumerate shares :
> `nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.82.245` - gives 3 shares 
- we will enumerate `anonymous` by doing `smbclient //10.10.82.245/anonymous` then when prompted for password just click enter and do `ls` we see `log.txt` 