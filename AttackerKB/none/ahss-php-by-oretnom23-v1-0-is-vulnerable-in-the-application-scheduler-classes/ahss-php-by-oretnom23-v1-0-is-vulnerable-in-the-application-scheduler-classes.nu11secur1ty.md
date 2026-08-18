---
title: 'AHSS-PHP (by: oretnom23 ) v1.0 is vulnerable in the application /scheduler/classes/Login.php to remote SQL-Injection-Bypass-Authentication + XSS-Stored Hijacking PHPSESSID'
author: nu11secur1ty
score: 1
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-09-15T11:44:20.223914'
revision_date: '2021-09-15T11:44:20.220247'
assessment_id: cf061e97-8d2b-404b-bc64-b446cf687db0
topic_id: 22292f97-fb9f-4690-9693-8a7e14535f0c
topic_short_id: hEkMnMjrlt
topic_slug: ahss-php-by-oretnom23-v1-0-is-vulnerable-in-the-application-scheduler-classes-login-php-to-remote-sql-injection-bypass-authentication-xss-stored-hijacking-phpsessid
akb_topic_url: https://attackerkb.com/topics/hEkMnMjrlt/ahss-php-by-oretnom23-v1-0-is-vulnerable-in-the-application-scheduler-classes-login-php-to-remote-sql-injection-bypass-authentication-xss-stored-hijacking-phpsessid
akb_assessment_url: https://attackerkb.com/topics/hEkMnMjrlt/ahss-php-by-oretnom23-v1-0-is-vulnerable-in-the-application-scheduler-classes-login-php-to-remote-sql-injection-bypass-authentication-xss-stored-hijacking-phpsessid#cf061e97-8d2b-404b-bc64-b446cf687db0
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# AHSS-PHP (by: oretnom23 ) v1.0 is vulnerable in the application /scheduler/classes/Login.php to remote SQL-Injection-Bypass-Authentication + XSS-Stored Hijacking PHPSESSID

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/hEkMnMjrlt/ahss-php-by-oretnom23-v1-0-is-vulnerable-in-the-application-scheduler-classes-login-php-to-remote-sql-injection-bypass-authentication-xss-stored-hijacking-phpsessid#cf061e97-8d2b-404b-bc64-b446cf687db0).*

---

## [CVE-nu11-11](https://www.sourcecodester.com/php/14902/simple-assembly-hall-scheduling-system-php-free-source-code.html)
![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/oretnom23/CVE-nu11-11/cookie_login.PNG)


## Description:
The AHSS-PHP (by: oretnom23 ) v1.0 is vulnerable in the application /scheduler/classes/Login.php to remote SQL-Injection-Bypass-Authentication + XSS-Stored Hijacking PHPSESSID
- m0re info: https://portswigger.net/support/using-sql-injection-to-bypass-authentication. 
The parameter (username) from the login form is not protected correctly and there is no security and escaping from malicious payloads. 
When the user will sending a malicious query or malicious payload to the MySQL server he can bypass the login credentials and take control of the administer account.
2. XSS - Stored PHPSESSID Vulnerable
- The vulnerable XSS app: is "manage_assembly", parameters: "room_name" "location" and "description"
After the successful SQL injection, the malicious user can be storing an XSS payload whit who can take the 
active PHPSESSID session.
3. remote PHPSESSID - Injection
- After the successful XSS attack the malicious user can take control of the administrative account of the system from everywhere 
by using the PHPSESSID, and then he can make a lot of bad things!

-------------------------------------------------------------------
### CONCLUSION: 
This vendor must STOP creating all these broken projects and vulnerable software programs, probably he is not a developer!

### BR 
- [+] @nu11secur1ty System Administrator - Infrastructure and Penetration Testing Engineer

-------------------------------------------------------------------
### Reproduce: 
[href](https://github.com/nu11secur1ty/CVE-nu11secur1ty/tree/main/vendors/oretnom23/CVE-nu11-11)

### Proof: 
[href](https://streamable.com/b8g00y)

### BR nu11secur1ty
