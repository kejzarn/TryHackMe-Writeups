# Traverse 

**Category:** Web <br> 
**Link:** [traverse](https://tryhackme.com/r/room/traverse) <br>
**Description:** Bob is a security engineer at a firm and works closely with the software/DevOps team to develop a tourism web application. Once the website was moved from QA to Production, the team noticed that the website was getting hacked daily and wanted to know the exact reason. Bob consulted the blue team as well but has yet to be successful. Therefore, he finally enrolled in the Software Security pathway at THM to learn if he was doing something wrong.
Deploy the machine by clicking the Start Machine button on the top right. You can access the website by visiting the URL http://x.x.x.x via your VPN connection or the AttackBox. Can you help Bob find the vulnerabilities and restore the website? <br>

# Initial reconnaissance & thoughts

I began by visiting the provided url, in my case http://10.10.205.169 (**this will differ in your case and you need to modify all urls**). The websited had obviously been hacked and it is our job to unhack it. 

![traverse/img/hacked.jpeg](https://github.com/kejzarn/TryHackMe-Writeups/blob/main/traverse/img/hacked.jpeg) <br>
Before starting my manual inspection I started a nikto scan with `nikto -h http://10.10.205.169`. As I performed my inspection I noticed some comments left by the hackers: <br>
![header](https://github.com/kejzarn/TryHackMe-Writeups/blob/main/traverse/img/header.png)

Which lead me to inspect `custom.min.js`. The file contained the following obfuscated message:

```
// I WILL KEEP THE OBFUSCATED SO NO ONE CAN UNDERSTAND

28 66 75 6E 63 74 69 6F 6E 28 29 7B 66 75 6E 63 74 69 6F 6E 20 64 6F 4E 6F 74 68 69 6E 67 28 29 7B 7D 76 61 72 20 6E 3D 22 44 49 52 45 43 54 4F 52 59 22 3B 76 61 72 20 65 3D 22 4C 49 53 54 49 4E 47 22 3B 76 61 72 20 6F 3D 22 49 53 20 54 48 45 22 3B 76 61 72 20 69 3D 22 4F 4E 4C 59 20 57 41 59 22 3B 76 61 72 20 66 3D 6E 75 6C 6C 3B 76 61 72 20 6C 3D 66 61 6C 73 65 3B 76 61 72 20 64 3B 69 66 28 66 3D 3D 3D 6E 75 6C 6C 29 7B 63 6F 6E 73 6F 6C 65 2E 6C 6F 67 28 22 46 6C 61 67 3A 22 2B 6E 2B 22 20 22 2B 65 2B 22 20 22 2B 6F 2B 22 20 22 2B 69 29 3B 64 3D 75 6E 64 65 66 69 6E 65 64 7D 65 6C 73 65 20 69 66 28 74 79 70 65 6F 66 20 66 3D 3D 3D 22 75 6E 64 65 66 69 6E 65 64 22 29 7B 64 3D 75 6E 64 65 66 69 6E 65 64 7D 65 6C 73 65 7B 69 66 28 6C 29 7B 64 3D 75 6E 64 65 66 69 6E 65 64 7D 65 6C 73 65 7B 28 66 75 6E 63 74 69 6F 6E 28 29 7B 69 66 28 64 29 7B 66 6F 72 28 76 61 72 20 6E 3D 30 3B 6E 3C 31 30 3B 6E 2B 2B 29 7B 63 6F 6E 73 6F 6C 65 2E 6C 6F 67 28 22 54 68 69 73 20 63 6F 64 65 20 64 6F 65 73 20 6E 6F 74 68 69 6E 67 2E 22 29 7D 64 6F 4E 6F 74 68 69 6E 67 28 29 7D 65 6C 73 65 7B 64 6F 4E 6F 74 68 69 6E 67 28 29 7D 7D 29 28 29 7D 7D 7D 29 28 29 3B
```

I recognise the format from hexadecimal format and like to utilise [hex analyser](https://www.boxentriq.com/code-breaking/hex-analysis) from [boxentriq.com](https://www.boxentriq.com) (remember to remove to comment!) the result is the follow:

```
(function(){function doNothing(){}var n="DIRECTORY";var e="LISTING";var o="IS THE";var i="ONLY WAY";var f=null;var l=false;var d;if(f===null){console.log("Flag:"+n+" "+e+" "+o+" "+i);d=undefined}else if(typeof f==="undefined"){d=undefined}else{if(l){d=undefined}else{(function(){if(d){for(var n=0;n<10;n++){console.log("This code does nothing.")}doNothing()}else{doNothing()}})()}}})();
```
This also answers a few questions for us: <br>
> **What type of encoding is used by the hackers to obfuscate the JavaScript file?**
> 
> ```
> Hex
> ```


By analysing the content of the derived function we get: 
> **What is the flag value after deobfuscating the file?**
> 
> ```
> DIRECTORY LISTING IS THE ONLY WAY
> ```

By now our Nikto scan should be completed the result is below, with some unnecessary data removed in the /***/ block so don't worry if yours don't look like that. 

```bash
root@ip-10-10-236-87:~# nikto -h 10.10.205.169
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.10.205.169
+ Target Hostname:    ip-10-10-205-169.eu-west-1.compute.internal
+ Target Port:        80
+ Start Time:         2024-09-10 14:20:39 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ Cookie PHPSESSID created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-3092: /client/: This might be interesting...
+ OSVDB-3268: /img/: Directory indexing found.
+ OSVDB-3092: /img/: This might be interesting...
+ OSVDB-3268: /logs/: Directory indexing found.
+ OSVDB-3092: /logs/: This might be interesting...
/***/
+ /phpmyadmin/: phpMyAdmin directory found
+ 6544 items checked: 0 error(s) and 23 item(s) reported on remote host
+ End Time:           2024-09-10 14:21:01 (GMT1) (22 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
The interesting parts are the directories /img/ and /logs/ there is also /phpmyadmin/ but that is not part of this CTF. 
Both  /img/ and /logs/ contains some files but the file `email_dump.txt` which is also the questions to the third question.

> **Logging is an important aspect. What is the name of the file containing email dumps?**
> 
> ```
> email_dump.txt
> ```

email_dump.txt contains the following message, and I've bolded the answers to question 4 and 5.

> From: Bob <bob@tourism.mht>
> To: Mark <mark@tourism.mht>
> Subject: API Credentials
>
> Hey Mark,
>
> Sorry I had to rush earlier for the holidays, but I have created the directory for you with all the required information for the API.
> You loved SSDLC so much, I named the **API folder under the name of the first phase of SSDLC**.
> This page is password protected and can only be opened through the key. **THM{100100111}**
>
> See ya after the holidays
> 
> Bob.
>
For the sake of consistency, the answers to question 4 and 5 : 


> **The logs folder contains email logs and has a message for the software team lead. What is the name of the directory that Bob has created?**
> 
> ```
> Planning
> ```

> **What is the key file for opening the directory that Bob has created for Mark?**
> 
> ```
> THM{100100111}
> ```

By going to the directory `/planning` and providing the password, THM{100100111} we recieve instructions for the endpoint `api/?customer_id=1`
With this we can answer the 6 question by inputing `http://x.x.x.x/api/?customer_id=5` in our browser and we retrieve the json object for customer with id 5:

```json
{
  "data": {
    "id": "5",
    "name": "John",
    "email": "john@traverse.com",
    "password": "qwerty5",
    "timestamp": "2023-05-23 04:47:25",
    "role": "user",
    "loginURL": "/client",
    "isadmin": "0"
  },
  "response_code": 200,
  "response_desc": "Success"
}

