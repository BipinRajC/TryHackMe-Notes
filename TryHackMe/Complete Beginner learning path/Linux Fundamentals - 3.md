
# Learning Path - Complete Beginner

## Linux fundamentals- part 3

- SCP command - secure means for copying files between remote host and local host using ssh protocol 
   copying files from local host to remote host:
   `$ scp important.txt ubuntu@192.168.1.30:/home/ubuntu/transferred.txt`

   copying files from remote host to local host:
   `$ scp ubuntu@192.168.1.30:/home/ubuntu/documents.txt notes.txt`
   ---
   

- Processes 101

![[Pasted image 20231104032034.png]]
***

- Automating processes - Cronjobs

syntax : 
`min hour dom mon dow cmd` [ * indicates every time of the day/month/year the cronjob takes place ]
example :
`0 *12 * * * cp -R /home/cmnatic/Documents /var/backups/` - backup happens every 12h every day every month of the year and so on of Documents directory into /var/backups

*Note - log files are found in the /var/log directory* (**cache**)

---
