
### **Hashing - Crypto 101**

- hash collision is when 2 different inputs give the same output
>MD5 collision - [here](https://www.mscs.dal.ca/~selinger/md5collision/)
>SHA1 collision - [here](https://shattered.io/)

- output size in bytes of md5 hash - `16 bytes`
- there's automated hash recognition tools - [tool](https://pypi.org/project/hashID/) to identify the type of hash
- standard format for Unix based hashes are 
> `$format$rounds$salt$hash` 
> windows passwords are hashed using NTLM which is a variant of md4
- on linux, password hashes are stored in `/etc/shadow` which can be read only by $root$ user 
- On Windows, password hashes are stored in the SAM. Windows tries to prevent normal users from dumping them, but tools like `mimikatz` exist for this. Importantly, the hashes found there are split into `NT hashes and LM hashes`.

###### Note :
1. `$1$` - md5crypt (used in cisco and older versions of linux)
2. `$2$, $2a$, $2b$, $2x$, $2y$` - Bcrypt (popular in web applications)
3. `$6$` - SHA512crypt (default in most linux/unix based systems)

>to find more examples - [hashcat example page](https://hashcat.net/wiki/doku.php?id=example_hashes) 

### _Password Cracking_

- try to use `hashcat` on host OS and not on VM because VM doesnt have access to host GPU and password cracking is much faster using multi cores present in GPU

- crack the hash - `$2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01pMSrddr1ZG` 
> we can say that it is `Bcrypt` so we use hashcat against `rockyou.txt` by doing
> `hashcat -m 3200 hash rockyou.txt`
> `hashcat -m 3200 hash rockyou.txt --force --show` 
> cracked = _85208520_

- crack the hash - `9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe614d4db30e8e1`
> analyzing on [online hash analyzer](https://www.tunnelsup.com/hash-analyzer/) we can say that it is `SHA256` hash
> `hashcat -m 1400 hash rockyou.txt`
> cracked = _halloween_

- crack the hash - `$6$GQXVvW4EuM$ehD6jWiMsfNorxy5SINsgdlxmAEl3.yif0/c3NqzGLa0P.S7KRDYjycw5bnYkF5ZtB8wQy8KnskuWQS3Yr1wQ0`
> we can say that the hash is `SHA512crypt`
> `hashcat -m 1800 hash rockyou.txt`
> cracked = _spaceman_

- crack the hash - `b6b0d451bbf6fed658659a9e7e5598fe`
> analyzing it on the site we can say it's `md5` hash 
> sometimes `rockyou` isnt always enough so we use online cracking sites instead comparing against a huge database - [decrypt here](https://hashtoolkit.com/decrypt-hash/?hash=) 
---

### _John the Ripper_

- online hash identifier - [here](https://hashes.com/en/tools/hash_identifier) 
- there is also a python tool which can identify hashes for you
	`python3 hash-id.py`
- to crack `hash1.txt`
> `john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt
> cracked = _biscuit_
- to crack `hash2.txt`
> `john --format=RAW-SHA1 --wordlist=/usr/share/wordlists/rockyou.txt hash2.txt`
> cracked = _kangeroo_
- to crack `hash3.txt`
> `john --format=RAW-SHA256 --wordlist=/usr/share/worldists/rockyou.txt hash3.txt
> cracked = _microphone_
- to crack `hash4.txt`, we put it in the python hash identifier and it is `WHIRLPOOL` 
> `john --format=whirlpool --wordlist=/usr/share/worldists/rockyou.txt hash4.txt`
> cracked = _colossal_

### _Cracking NTLM hashes_

- NT hash is the hash format that modern Windows Operating System machines will store user and service passwords in.
- You can acquire NTHash/NTLM hashes by dumping the SAM database on a Windows machine, by using a tool like `Mimikatz` or from the Active Directory database
- to crack `NTLM.txt` 
> `john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt ntlm.txt
> cracked = _mushroom_

### _Cracking /etc/shadow hashes_

- `unshadow` is a tool built into John suite of tools. In order to crack `/etc/shadow` passwords, you must combine it with the `/etc/passwd` file in order for John to understand the data it's being given
`unshadow [path to passwd] [path to shadow]`
- to understand more of `/etc/shadow` file, read [here](https://www.cyberciti.biz/faq/understanding-etcshadow-file/) 
- reading the contents of `etchashes.txt` :
```
This is everything I managed to recover from the target machine before my computer crashed... See if you can crack the hash so we can at least salvage a password to try and get back in.

root:x:0:0::/root:/bin/bash
root:$6$Ha.d5nGupBm29pYr$yugXSk24ZljLTAZZagtGwpSQhb3F2DOJtnHrvk7HI2ma4GsuioHp8sm3LJiRJpKfIf7lZQ29qgtH17Q/JDpYM/:18576::::::
```
- first we unshadow and map the `/etc/passwd` to `/etc/shadow` by doing 
> `unshadow passwd shadow > unshadowed.txt` 
>`john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt`
   cracked = _1234_

### _Single Crack Mode_

- we have to prepend the username to use in single crack mode so that `john` can automatically do `word mangling` 
- make `hash7.txt` - `joker:7bf6d9bb82bed1302f331fc6b816aada`
>`john --single --format=raw-md5 hash7.txt`
>cracked = _Jok3r_ 

### _Custom Rules_

- We have a comprehensive set of rules to edit the `/etc/john/john.conf` file in this [wiki page](https://www.openwall.com/john/doc/RULES.shtml) 
- good overview can be found - [here](https://cheatography.com/davechild/cheat-sheets/regular-expressions/) 
- **What rule would we use to add all capital letters to the end of the word?**
> `Az"[A-Z]"` 

### _Cracking password protected zip files & RAR archives_

- tool - `Zip2John` 
> `zip2john zipfile.zip > zip_hash.txt` 
- now we do `john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt`

- tool - `rar2john`
> `rar2john secure.rar > rar_hash.txt
- `john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt`
- to access flag.txt within rar file, do `unrar x secure.rar` and enter password that we cracked when prompted.

### _Cracking SSH Key Passwords_

- tool - `ssh2john` 
> `ssh2john idrsa.id_rsa > rsa_hash.txt`
- `john --wordlist=/usr/share/wordlists/rockyou.txt rsa_hash.txt`
- cracked password = `mango`
---
# Encryption 101

- RSA for CTFs - tool that comes in handy is [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) 
- The math behind RSA - [RSA math](https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/) 
- How HTTPS actually works - [Https working](https://robertheaton.com/2014/03/27/how-does-https-actually-work/) 

- By default, ssh keys are RSA keys, You can choose which algorithm to generate, and/or add a passphrase to encrypt the SSH key. `ssh-keygen` is the program used to generate pairs of keys most of the time.
- visual representation of [Diffie Helmann Key Exchange](https://www.youtube.com/watch?v=NmM9HA2MQGI) 
### _PGP/GPG Cracking_

- tool - `gpg2john` (gpg is used to encrypt files and messages and to sign files and messages)
- but here in task files we've been given `tryhackme.key` and `message.gpg` and we do the following to decrypt the message
> `gpg --import tryhackme.key`
> `gpg --output message.txt --decrypt message.gpg` - this gives us the secret word `Pineapple`
---
