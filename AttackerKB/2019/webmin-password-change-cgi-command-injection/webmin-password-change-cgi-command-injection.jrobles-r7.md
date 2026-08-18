---
title: Webmin password_change.cgi Command Injection
author: jrobles-r7
score: 2
topic_attacker_value: 5
topic_exploitability: 4.777777777777778
topic_disclosure_date: '2019-08-16T03:15:00'
created: '2019-08-20T18:02:54.508118'
revision_date: '2020-04-28T21:38:36.664504'
assessment_id: 51e9af72-003f-4e05-a8a3-2a53c8a8da27
topic_id: ea90a258-8e7f-49cd-a730-6d8457a421d7
topic_short_id: hxx3zmiCkR
topic_slug: webmin-password-change-cgi-command-injection
akb_topic_url: https://attackerkb.com/topics/hxx3zmiCkR/webmin-password-change-cgi-command-injection
akb_assessment_url: https://attackerkb.com/topics/hxx3zmiCkR/webmin-password-change-cgi-command-injection#51e9af72-003f-4e05-a8a3-2a53c8a8da27
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 5
  effort-to-develop-exploit: 1
  exploitability: 5
  urgent-to-patch: 5
  used-successfully: 5
---

# Webmin password_change.cgi Command Injection

*Assessment by jrobles-r7, archived from [AttackerKB](https://attackerkb.com/topics/hxx3zmiCkR/webmin-password-change-cgi-command-injection#51e9af72-003f-4e05-a8a3-2a53c8a8da27).*

---

I tested Webmin v1.900 and the password change page was not available by default, however it is a reasonable option to have.
A valid username is not needed for the exploit, although the command injection did not work for me when I used the valid username `root`.
