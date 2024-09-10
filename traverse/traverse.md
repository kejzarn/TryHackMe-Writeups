# Traverse 

**Category:** Web <br> 
**Link:** [traverse](https://tryhackme.com/r/room/traverse) <br>
**Description:** Bob is a security engineer at a firm and works closely with the software/DevOps team to develop a tourism web application. Once the website was moved from QA to Production, the team noticed that the website was getting hacked daily and wanted to know the exact reason. Bob consulted the blue team as well but has yet to be successful. Therefore, he finally enrolled in the Software Security pathway at THM to learn if he was doing something wrong.
Deploy the machine by clicking the Start Machine button on the top right. You can access the website by visiting the URL http://x.x.x.x via your VPN connection or the AttackBox. Can you help Bob find the vulnerabilities and restore the website? <br>

## Table of Contents

- [Initial reconnaissance & thoughts](#Initial-reconnaissance-&--thoughts)
- [What type of encoding is used by the hackers to obfuscate the JavaScript file?](#what-type-of-encoding-is-used-by-the-hackers-to-obfuscate-the-javascript-file)
- [What is the flag value after deobfuscating the file?](#what-is-the-flag-value-after-deobfuscating-the-file)
- [Logging is an important aspect. What is the name of the file containing email dumps?](#logging-is-an-important-aspect-what-is-the-name-of-the-file-containing-email-dumps)
- [The logs folder contains email logs and has a message for the software team lead. What is the name of the directory that Bob has created?](#the-logs-folder-contains-email-logs-and-has-a-message-for-the-software-team-lead-what-is-the-name-of-the-directory-that-bob-has-created)
- [What is the key file for opening the directory that Bob has created for Mark?](#what-is-the-key-file-for-opening-the-directory-that-bob-has-created-for-mark)
- [What is the email address for ID 5 using the leaked API endpoint?](#what-is-the-email-address-for-id-5-using-the-leaked-api-endpoint)
- [What is the ID for the user with admin privileges?](#what-is-the-id-for-the-user-with-admin-privileges)
- [What is the endpoint for logging in as the admin? Mention the last endpoint instead of the URL. For example, if the answer is URL is tryhackme.com/admin - Just write /admin.](#what-is-the-endpoint-for-logging-in-as-the-admin-mention-the-last-endpoint-instead-of-the-url-for-example-if-the-answer-is-url-is-tryhackmecomadmin---just-write-admin)
- [The attacker uploaded a web shell and renamed a file used for managing the server. Can you find the name of the web shell that the attacker has uploaded?](#the-attacker-uploaded-a-web-shell-and-renamed-a-file-used-for-managing-the-server-can-you-find-the-name-of-the-web-shell-that-the-attacker-has-uploaded)
- [What is the name of the file renamed by the attacker for managing the web server?](#what-is-the-name-of-the-file-renamed-by-the-attacker-for-managing-the-web-server)
- [Can you use the file manager to restore the original website by removing the "FINALLY HACKED" message? What is the flag value after restoring the main website?](#can-you-use-the-file-manager-to-restore-the-original-website-by-removing-the-finally-hacked-message-what-is-the-flag-value-after-restoring-the-main-website)
- [](#Conclussions)

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
> ### **What type of encoding is used by the hackers to obfuscate the JavaScript file?**
> 
> ```
> Hex
> ```


By analysing the content of the derived function we get: 
> ### **What is the flag value after deobfuscating the file?**
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

> ### **Logging is an important aspect. What is the name of the file containing email dumps?**
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


> ### **The logs folder contains email logs and has a message for the software team lead. What is the name of the directory that Bob has created?**
> 
> ```
> Planning
> ```

> ### **What is the key file for opening the directory that Bob has created for Mark?**
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
```
This gives the answer to question 6. 

> ### **What is the email address for ID 5 using the leaked API endpoint?**
> 
> ```
> john@traverse.com
> ```

Continue travering over the customer id api from 0 - n until you find the admin, which will be `http://x.x.x.x/api/?customer_id=3` and thus answering question 7.

```json
{
  "data": {
    "id": "3",
    "name": "admin",
    "email": "realadmin@traverse.com",
    "password": "admin_key!!!",
    "timestamp": "2023-05-23 04:47:25",
    "role": "admin",
    "loginURL": "/realadmin",
    "isadmin": "1"
  },
  "response_code": 200,
  "response_desc": "Success"
}
```


> ### **What is the ID for the user with admin privileges?**
> 
> ```
> 3
> ```

This furthermore provides important information for continue our exploitation, we are given the username `realadmin@traverse.com`, the password `admin_key!!!` and corresponding login url `/realadmin` we procced to http://x.x.x.x/realadmin and provide the username & password and we are logged on to the admin portal! 

Here we are meet with a command prompt which has two options for commands `System Owner`and `Current Directory` with the option to execute the commands. Executing `System Owner` returns a `www-data`, my guess is that this is the response from a `whoami` command.  
Other than that I see little options for continuing deeper, thus I believe the way forward is to see if can intercept the exectuin commands and modify to our will so I spin up burp and intercept a `System Owner` command. 

```html
POST /realadmin/main.php HTTP/1.1
Host: 10.10.205.169
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 11
Origin: http://10.10.212.202
Connection: close
Referer: http://10.10.212.202/realadmin/main.php
Cookie: PHPSESSID=il1s5f3ftavehmfs37j5d9nu5n
Upgrade-Insecure-Requests: 1

commands=whoami
```
As suspected we forward a `whoami`command to the server, I modify to a `ls` to list all files in our current directory, to get an understanding what is in there and what we are working with. We hit jackpot and find several things we are looking for: 

![adminportal](https://github.com/kejzarn/TryHackMe-Writeups/blob/main/traverse/img/adminportal.png)

We recognise two directories we already visited `index.php` and `main.php` additionally we have `thm_shell.php` and `renamed_file_manager.php` and an access key to the file manager `THM{10101}`. 

This information provides answers to two questions, question 9 and 10: 

> ### **The attacker uploaded a web shell and renamed a file used for managing the server. Can you find the name of the web shell that the attacker has uploaded?**
> 
> ```
> thm_shell.php
> ```

> ### **What is the name of the file renamed by the attacker for managing the web server?**
> 
> ```
> renamed_file_manager.php
> ```

Which leaves our final question! We attempt to access `http://x.x.x.x/realadmin/renamed_file_manager.php` with username predefind as `admin` and password `THM{10101}` and we are in the fill manager! 

From here you can navigate to all files building up the website and change as you are like, our quest remains to save the website after search a little while we find the `index.php`

```php
<!-- Rest PHP code and HTML content -->
<?php
include './api/login.php';
$basePath = "/";
?>

<!DOCTYPE html>
<html lang="en">

<?php
include 'header.php';
$message = "FINALLY HACKED";
?>

<!-- Main Content -->
<main class="mx-auto py-8 h-[80vh] flex items-center justify-center">
  <div class="rounded overflow-hidden shadow-lg bg-white p-8 flex ">
    <?php
    if ($message != "FINALLY HACKED") {
      echo '<h1 class="text-gray-700 text-3xl py-6"> SUCCESSFULLY RESTORED WEBSITE FLAG: THM{WEBSITE_RESTORED}</h1>';
    } else {
      ?>
      <h2 class="text-gray-700 text-3xl py-6"> <?php echo $message; ?> !!! I HATE MINIFIED JAVASCRIPT</h2>
      <?php
    }
    ?>
  </div>
</main>

<?php
include 'footer.php';
?>
</body>
</html>
```
What we are after here is to remove or change the value of `$message` as the code snippet reveals as long as the message is `FINALLY HACKED` we primary content will be locked. By removing this (or by simply looking at the code) we retrive the final flag `THM{WEBSITE_RESTORED}`.

> ### **Can you use the file manager to restore the original website by removing the **FINALLY HACKED** message? What is the flag value after restoring the main website?**
> 
> ```
> THM{WEBSITE_RESTORED}
> ```

![restored](https://github.com/kejzarn/TryHackMe-Writeups/blob/main/traverse/img/restored.png)

Success! We restored the website! 

# Conclussions 
Additionally, after this, we would normally advise on the following improvements:

- **Not allowing logs to be accessed from the public directory**
- **Utilizing encrypted emails** (and probably some security awareness training)
- **Endpoint protection**: It is possible to access `api/?customer_id=1` without being logged in
- **IAM**: Even if we protect the endpoint only priveleged users should be able to access the database and see certain users
- **Encryption**: Passwords should never stored in plaintext but should rather be stored in in their hashed value, preferably with a salt.
- **Server Side Validation**: As security engineers we know we cannot trust the frontend, if we for some reason decide to have a shell on the frontend we need to validated the input on the backend and define an allowlist.

The CTF in itself was fun with a somewhat redline between the different goals. 




