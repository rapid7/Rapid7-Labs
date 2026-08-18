---
title: 'SQL Injection - bypass login on B&E Tracker (by: oretnom23 ) v1.0'
author: nu11secur1ty
score: 1
topic_attacker_value: 5
topic_exploitability: 5
created: '2021-08-25T09:43:58.645051'
revision_date: '2021-08-25T09:43:58.645629'
assessment_id: 8ddc7257-dcba-48db-95e6-d31bf8282d0f
topic_id: ea650aec-1792-4d2f-9e86-7792e578df10
topic_short_id: e12ZvzjAwr
topic_slug: sql-injection---bypass-login-on-b-e-tracker-by-oretnom23-v1-0
akb_topic_url: https://attackerkb.com/topics/e12ZvzjAwr/sql-injection---bypass-login-on-b-e-tracker-by-oretnom23-v1-0
akb_assessment_url: https://attackerkb.com/topics/e12ZvzjAwr/sql-injection---bypass-login-on-b-e-tracker-by-oretnom23-v1-0#8ddc7257-dcba-48db-95e6-d31bf8282d0f
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Execution
---

# SQL Injection - bypass login on B&E Tracker (by: oretnom23 ) v1.0

*Assessment by nu11secur1ty, archived from [AttackerKB](https://attackerkb.com/topics/e12ZvzjAwr/sql-injection---bypass-login-on-b-e-tracker-by-oretnom23-v1-0#8ddc7257-dcba-48db-95e6-d31bf8282d0f).*

---

# Description:
The B&E Tracker (by: oretnom23 ) v1.0 is vulnerable
in the application /expense_budget/classes/Login.php which is called from /expense_budget/dist/js/script.js app. 
The parameter (username) from the login form is not protected correctly and there is no security and escaping from malicious payloads. 
When the user is sending a request to the MySQL server he can bypass the login credentials and take control of the administer account.
# Reproduce:
https://github.com/nu11secur1ty/CVE-nu11secur1ty/tree/main/vendors/B%26E%20Tracker-by:oretnom23-v1.0
# Proof:
https://streamable.com/y3ig5h
# BR nu11secur1ty
