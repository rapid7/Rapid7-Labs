---
title: SES-by-oretnom23 -v1.0-SQL-Injection-bypass-Login
author: nu11secur1ty
score: 2
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-08-25T16:40:45.791884'
revision_date: '2021-09-01T15:19:19.304236'
assessment_id: 6e444ff3-cc36-43ae-a7f5-b85461b2bd34
topic_id: bad73e56-8c5c-4884-850e-b6f60ee4b516
topic_short_id: nGjPKzB9PX
topic_slug: ses-by-oretnom23--v1-0-sql-injection-bypass-login
akb_topic_url: https://attackerkb.com/topics/nGjPKzB9PX/ses-by-oretnom23--v1-0-sql-injection-bypass-login
akb_assessment_url: https://attackerkb.com/topics/nGjPKzB9PX/ses-by-oretnom23--v1-0-sql-injection-bypass-login#6e444ff3-cc36-43ae-a7f5-b85461b2bd34
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# SES-by-oretnom23 -v1.0-SQL-Injection-bypass-Login

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/nGjPKzB9PX/ses-by-oretnom23--v1-0-sql-injection-bypass-login#6e444ff3-cc36-43ae-a7f5-b85461b2bd34).*

---

The SES-by_oretnom23 -v1.0 is vulnerable in the application /elearning/classes/Login.php which is called from /elearning/dist/js/script.js app. The parameter (username) from the login form is not protected correctly and there is no security and escaping from malicious payloads. When the user is sending a request to the MySQL server he can bypass the login credentials and take control of the administer account.

## Reproduce:
https://github.com/nu11secur1ty/CVE-nu11secur1ty/tree/main/vendors/SES-by_oretnom23%20-v1.0

## Proof:
https://streamable.com/kswjbi
