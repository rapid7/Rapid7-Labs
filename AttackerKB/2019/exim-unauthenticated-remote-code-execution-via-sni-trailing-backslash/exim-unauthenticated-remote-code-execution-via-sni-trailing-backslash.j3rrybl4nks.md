---
title: Exim Unauthenticated Remote Code Execution via SNI Trailing Backslash
author: J3rryBl4nks
score: 3
topic_attacker_value: 5
topic_exploitability: 5
topic_disclosure_date: '2019-09-06T11:15:00'
created: '2020-03-03T16:27:33.688956'
revision_date: '2020-03-24T03:22:19.935651'
assessment_id: 22950971-c345-4c02-bff0-6c2649c45293
topic_id: d2c5f192-f965-4d8e-8fcc-126183f9124a
topic_short_id: wSXxVHOwyV
topic_slug: exim-unauthenticated-remote-code-execution-via-sni-trailing-backslash
akb_topic_url: https://attackerkb.com/topics/wSXxVHOwyV/exim-unauthenticated-remote-code-execution-via-sni-trailing-backslash
akb_assessment_url: https://attackerkb.com/topics/wSXxVHOwyV/exim-unauthenticated-remote-code-execution-via-sni-trailing-backslash#22950971-c345-4c02-bff0-6c2649c45293
author_ratings:
  attacker-value: 5
  exploitability: 5
  tags:
  - default_configuration
  - high_privilege_access
  - easy_to_develop
---

# Exim Unauthenticated Remote Code Execution via SNI Trailing Backslash

*Assessment by J3rryBl4nks, archived from [AttackerKB](https://attackerkb.com/topics/wSXxVHOwyV/exim-unauthenticated-remote-code-execution-via-sni-trailing-backslash#22950971-c345-4c02-bff0-6c2649c45293).*

---

Due to public exploits being available : https://github.com/synacktiv/Exim-CVE-2019-15846, and the fact that Exim is installed on a large number of mail servers, the value to an attacker lies in the fact that this requires no authentication.

There is a deeper explanation of the vulnerability here: https://www.synacktiv.com/posts/exploit/scraps-of-notes-on-exploiting-exim-vulnerabilities.html
