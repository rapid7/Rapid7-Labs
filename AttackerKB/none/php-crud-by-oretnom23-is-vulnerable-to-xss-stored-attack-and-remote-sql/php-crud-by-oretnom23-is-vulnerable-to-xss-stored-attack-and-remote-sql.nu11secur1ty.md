---
title: 'PHP CRUD (by: oretnom23 ) is vulnerable to XSS Stored Attack and remote SQL-Injection special characters no prepared statements'
author: nu11secur1ty
score: 1
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-09-10T09:01:14.601242'
revision_date: '2021-09-10T10:55:31.479172'
assessment_id: ba2ebb74-6b82-4a79-86e2-53e52fdd484b
topic_id: 9ad5c932-664b-45c3-a537-b1bfa45f73a5
topic_short_id: kzCIxDxP1F
topic_slug: php-crud-by-oretnom23-is-vulnerable-to-xss-stored-attack-and-remote-sql-injection-special-characters-no-prepared-statements
akb_topic_url: https://attackerkb.com/topics/kzCIxDxP1F/php-crud-by-oretnom23-is-vulnerable-to-xss-stored-attack-and-remote-sql-injection-special-characters-no-prepared-statements
akb_assessment_url: https://attackerkb.com/topics/kzCIxDxP1F/php-crud-by-oretnom23-is-vulnerable-to-xss-stored-attack-and-remote-sql-injection-special-characters-no-prepared-statements#ba2ebb74-6b82-4a79-86e2-53e52fdd484b
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# PHP CRUD (by: oretnom23 ) is vulnerable to XSS Stored Attack and remote SQL-Injection special characters no prepared statements

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/kzCIxDxP1F/php-crud-by-oretnom23-is-vulnerable-to-xss-stored-attack-and-remote-sql-injection-special-characters-no-prepared-statements#ba2ebb74-6b82-4a79-86e2-53e52fdd484b).*

---

## [CVE-nu11-10-09102021](https://www.sourcecodester.com/tutorial/14937/php-crud-without-refreshreload-using-ajax-and-datatables-tutorial)
![](https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/oretnom23/CVE-nu11-10-09102021/docs/Capture.PNG)

## [Vendor](https://www.sourcecodester.com/users/tips23)

### Description:
The PHP CRUD (by: oretnom23 ) is vulnerable to XSS Stored Attack and remote SQL-Injection special characters. 
In the application: ajax_crud the parameters, first_name, last_name, and email are vulnerable to XSS Stored attack!
When the user will sending a malicious javascript payload, he can store a special character - string, onto the MySQL server. 
The MySQL server can't read it because there have no prepared statements or the appropriate replacement/formatting rules 
in order to prevent SQL injection and the system will be down.
Status: CRITICAL

## Documentation, HOW TO CHARACTER SET Statement:
[href](https://dev.mysql.com/doc/refman/5.7/en/set-character-set.html)

## Proof:
[href](https://streamable.com/8n85yf)
