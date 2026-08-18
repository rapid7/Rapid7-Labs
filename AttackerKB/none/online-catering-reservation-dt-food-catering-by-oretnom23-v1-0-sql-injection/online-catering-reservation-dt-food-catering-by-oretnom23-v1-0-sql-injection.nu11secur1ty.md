---
title: 'Online-Catering-Reservation-DT Food Catering (by: oretnom23 ) v1.0 SQL injection - login'
author: nu11secur1ty
score: 1
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-08-24T10:27:47.247786'
revision_date: '2021-08-26T16:13:48.1157'
assessment_id: d8c5cc55-995a-44ca-8d60-5e7139a74274
topic_id: 7dd22e12-dc79-418f-a67e-debc167dbdbe
topic_short_id: XuEb81tsid
topic_slug: online-catering-reservation-dt-food-catering-by-oretnom23-v1-0-sql-injection---login
akb_topic_url: https://attackerkb.com/topics/XuEb81tsid/online-catering-reservation-dt-food-catering-by-oretnom23-v1-0-sql-injection---login
akb_assessment_url: https://attackerkb.com/topics/XuEb81tsid/online-catering-reservation-dt-food-catering-by-oretnom23-v1-0-sql-injection---login#d8c5cc55-995a-44ca-8d60-5e7139a74274
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Credential Access
---

# Online-Catering-Reservation-DT Food Catering (by: oretnom23 ) v1.0 SQL injection - login

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/XuEb81tsid/online-catering-reservation-dt-food-catering-by-oretnom23-v1-0-sql-injection---login#d8c5cc55-995a-44ca-8d60-5e7139a74274).*

---

## Description:
The Online-Catering-Reservation-DT Food-Catering(by: oretnom23)v1.0 is vulnerable
in the application /catering/classes/Login.php which is called from /catering/dist/js/script.js app. 
The parameter (username) from the login form is not protected correctly and there is no security and escaping from malicious payloads. 
When the user is sending a request to the MySQL server he can bypass the login credentials and take control of the administer account.

## More: 
https://www.nu11secur1ty.com/2021/08/online-catering-reservation-dt-sql.html
## More: 
https://github.com/nu11secur1ty/CVE-mitre/tree/main/Online-Catering-Reservation-DT-Food-Catering

- and on the owner of the exploit, on the home page: 
https://www.nu11secur1ty.com/2021/08/online-catering-reservation-dt-sql.html

## Simple proof and simple fix but not strong! =)
https://streamable.com/7qfnkl

## BR
