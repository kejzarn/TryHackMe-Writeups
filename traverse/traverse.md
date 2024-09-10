# Traverse 

**Category:** Web <br> 
**Link:** [traverse](https://tryhackme.com/r/room/traverse) <br>
**Description:** Bob is a security engineer at a firm and works closely with the software/DevOps team to develop a tourism web application. Once the website was moved from QA to Production, the team noticed that the website was getting hacked daily and wanted to know the exact reason. Bob consulted the blue team as well but has yet to be successful. Therefore, he finally enrolled in the Software Security pathway at THM to learn if he was doing something wrong.
Deploy the machine by clicking the Start Machine button on the top right. You can access the website by visiting the URL http://x.x.x.x via your VPN connection or the AttackBox. Can you help Bob find the vulnerabilities and restore the website? <br>

# Initial reconnaissance & thoughts

I began by visiting the provided url, in my case http://10.10.205.169 (**this will differ in your case and you need to modify all urls**). The websited had obviously been hacked and it is our job to unhack it. Before starting my manual inspection I started a nikto scan with `nikto -h http://10.10.205.169`. As I performed my inspection I noticed some comments left by the hackers: <br>


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
+ Cookie phpMyAdmin created without the httponly flag
+ Cookie goto created without the httponly flag
+ Cookie back created without the httponly flag
+ Cookie pma_lang created without the httponly flag
+ Uncommon header 'x-content-security-policy' found, with contents: default-src 'self' ;options inline-script eval-script;referrer no-referrer;img-src 'self' data:  *.tile.openstreetmap.org;object-src 'none';
+ Uncommon header 'referrer-policy' found, with contents: no-referrer
+ Uncommon header 'x-xss-protection' found, with contents: 1; mode=block
+ Uncommon header 'x-robots-tag' found, with contents: noindex, nofollow
+ Uncommon header 'x-content-type-options' found, with contents: nosniff
+ Uncommon header 'x-ob_mode' found, with contents: 1
+ Uncommon header 'x-webkit-csp' found, with contents: default-src 'self' ;script-src 'self'  'unsafe-inline' 'unsafe-eval';referrer no-referrer;style-src 'self' 'unsafe-inline' ;img-src 'self' data:  *.tile.openstreetmap.org;object-src 'none';
+ Uncommon header 'content-security-policy' found, with contents: default-src 'self' ;script-src 'self' 'unsafe-inline' 'unsafe-eval' ;style-src 'self' 'unsafe-inline' ;img-src 'self' data:  *.tile.openstreetmap.org;object-src 'none';
+ Uncommon header 'x-permitted-cross-domain-policies' found, with contents: none
+ Uncommon header 'x-frame-options' found, with contents: DENY
+ /phpmyadmin/: phpMyAdmin directory found
+ 6544 items checked: 0 error(s) and 23 item(s) reported on remote host
+ End Time:           2024-09-10 14:21:01 (GMT1) (22 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
aa
