---
title: Exim SMTP server RCE via base64d
author: asoto-r7
score: 1
topic_attacker_value: 4
topic_exploitability: 0
topic_disclosure_date: '2018-02-08T23:29:00'
created: '2019-06-25T18:25:51.108791'
revision_date: '2020-02-13T17:12:34.13386'
assessment_id: 1c21081c-ef63-4c20-a699-b66cf3c637c4
topic_id: 63c1e977-b118-475c-8c47-1046b294e1ba
topic_short_id: s2eAU0s76p
topic_slug: exim-smtp-server-rce-via-base64d
akb_topic_url: https://attackerkb.com/topics/s2eAU0s76p/exim-smtp-server-rce-via-base64d
akb_assessment_url: https://attackerkb.com/topics/s2eAU0s76p/exim-smtp-server-rce-via-base64d#1c21081c-ef63-4c20-a699-b66cf3c637c4
author_ratings:
  attacker-value: 4
  confidence-in-ratings: 3
  urgent-to-patch: 5
  used-successfully: 1
---

# Exim SMTP server RCE via base64d

*Assessment by asoto-r7, archived from [AttackerKB](https://attackerkb.com/topics/s2eAU0s76p/exim-smtp-server-rce-via-base64d#1c21081c-ef63-4c20-a699-b66cf3c637c4).*

---

There are a few PoCs for this one.  Exim is a bear to setup and I wouldn't be shocked to find unpatched servers because sysadmins don't want to touch them.  Since they'd be Internet-accessible, there's a lot of attacker utility here for the small population that uses Exim.
