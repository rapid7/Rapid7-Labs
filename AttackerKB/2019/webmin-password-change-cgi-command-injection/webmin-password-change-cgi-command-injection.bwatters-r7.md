---
title: Webmin password_change.cgi Command Injection
author: bwatters-r7
score: 3
topic_attacker_value: 5
topic_exploitability: 4.777777777777778
topic_disclosure_date: '2019-08-16T03:15:00'
created: '2019-08-22T22:22:18.978998'
revision_date: '2020-02-13T17:12:27.614881'
assessment_id: aed990bb-8f2e-4a05-a7f9-bb2f81e5d94c
topic_id: ea90a258-8e7f-49cd-a730-6d8457a421d7
topic_short_id: hxx3zmiCkR
topic_slug: webmin-password-change-cgi-command-injection
akb_topic_url: https://attackerkb.com/topics/hxx3zmiCkR/webmin-password-change-cgi-command-injection
akb_assessment_url: https://attackerkb.com/topics/hxx3zmiCkR/webmin-password-change-cgi-command-injection#aed990bb-8f2e-4a05-a7f9-bb2f81e5d94c
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 4
  effort-to-develop-exploit: 1
  exploitability: 5
  urgent-to-patch: 5
  used-successfully: 1
---

# Webmin password_change.cgi Command Injection

*Assessment by bwatters-r7, archived from [AttackerKB](https://attackerkb.com/topics/hxx3zmiCkR/webmin-password-change-cgi-command-injection#aed990bb-8f2e-4a05-a7f9-bb2f81e5d94c).*

---

This is a terrible situation for any development team.  A hacker took over a server that managed webmin code and changed the code in a subtle way to allow them (or others) to execute commands as root on computers running Webmin.  It took nearly a year and a half for the attack to be discovered and fixed.
