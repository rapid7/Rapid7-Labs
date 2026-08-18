---
title: South Gate Inn Online Reservation System © South Gate Inn is vulnerable to remote SQL-Injection-Bypass-Authentication for the admin account and XSS-Stored PWNED
author: nu11secur1ty
score: 1
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-09-16T10:48:28.970053'
revision_date: '2021-09-16T10:51:24.347757'
assessment_id: 5abb97dd-a083-4ffb-9e3e-c24ada4735e7
topic_id: 4fed6a8c-2dcc-4751-8108-657304e22955
topic_short_id: fxw53M0EAJ
topic_slug: south-gate-inn-online-reservation-system-south-gate-inn-is-vulnerable-to-remote-sql-injection-bypass-authentication-for-the-admin-account-and-xss-stored-pwned
akb_topic_url: https://attackerkb.com/topics/fxw53M0EAJ/south-gate-inn-online-reservation-system-south-gate-inn-is-vulnerable-to-remote-sql-injection-bypass-authentication-for-the-admin-account-and-xss-stored-pwned
akb_assessment_url: https://attackerkb.com/topics/fxw53M0EAJ/south-gate-inn-online-reservation-system-south-gate-inn-is-vulnerable-to-remote-sql-injection-bypass-authentication-for-the-admin-account-and-xss-stored-pwned#5abb97dd-a083-4ffb-9e3e-c24ada4735e7
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# South Gate Inn Online Reservation System © South Gate Inn is vulnerable to remote SQL-Injection-Bypass-Authentication for the admin account and XSS-Stored PWNED

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/fxw53M0EAJ/south-gate-inn-online-reservation-system-south-gate-inn-is-vulnerable-to-remote-sql-injection-bypass-authentication-for-the-admin-account-and-xss-stored-pwned#5abb97dd-a083-4ffb-9e3e-c24ada4735e7).*

---

## [CVE-nu11-12-09162021](https://www.sourcecodester.com/php/10584/south-gate-inn-online-reservation-system.html)
![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/janobe/CVE-nu11-12-09162021/docs/southgateinnps.asd_.sad__1.png)

### Description:
The South Gate Inn Online Reservation System © South Gate Inn is vulnerable to remote SQL-Injection-Bypass-Authentication for the admin account and XSS-Stored PWNED.
remote SQL-Injection-Bypass-Authentication: https://portswigger.net/support/using-sql-injection-to-bypass-authentication. 
The parameters (email and Password) from the login form are not protected correctly and there is no security and escaping from malicious payloads. 
When the user will sending a malicious query or malicious payload to the MySQL server for login to the admin account on the system, 
he can bypass the login credentials and take control of this account. 
And the second time he can access the admin account and adding a payload by using the XSS-Stored technique which can break the MySQL server.

### Reproduce:
[href](https://github.com/nu11secur1ty/CVE-nu11secur1ty/tree/main/vendors/janobe/CVE-nu11-12-09162021)

## Proof:
[href](https://streamable.com/a2ym1t)
