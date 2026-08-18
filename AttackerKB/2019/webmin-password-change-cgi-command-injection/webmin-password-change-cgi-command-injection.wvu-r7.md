---
title: Webmin password_change.cgi Command Injection
author: wvu-r7
score: 15
topic_attacker_value: 5
topic_exploitability: 4.777777777777778
topic_disclosure_date: '2019-08-16T03:15:00'
created: '2019-08-21T03:12:09.798196'
revision_date: '2024-01-08T08:13:39.033094'
assessment_id: 4601b37d-1e68-494e-be8b-c45be7ad424c
topic_id: ea90a258-8e7f-49cd-a730-6d8457a421d7
topic_short_id: hxx3zmiCkR
topic_slug: webmin-password-change-cgi-command-injection
akb_topic_url: https://attackerkb.com/topics/hxx3zmiCkR/webmin-password-change-cgi-command-injection
akb_assessment_url: https://attackerkb.com/topics/hxx3zmiCkR/webmin-password-change-cgi-command-injection#4601b37d-1e68-494e-be8b-c45be7ad424c
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 5
  effort-to-develop-exploit: 1
  exploitability: 5
  urgent-to-patch: 5
  used-successfully: 5
---

# Webmin password_change.cgi Command Injection

*Assessment by wvu-r7, archived from [AttackerKB](https://attackerkb.com/topics/hxx3zmiCkR/webmin-password-change-cgi-command-injection#4601b37d-1e68-494e-be8b-c45be7ad424c).*

---

This was a supply chain attack: http://www.webmin.com/exploit.html. The backdoor was introduced in a version that was "exploitable" in the default install. Version 1.890 is the money. Anything after requires a non-default setting.

Note that SourceForge installs are affected, but GitHub checkouts aren't.

ETA: Metasploit added an [exploit module](https://github.com/rapid7/metasploit-framework/pull/12219).
