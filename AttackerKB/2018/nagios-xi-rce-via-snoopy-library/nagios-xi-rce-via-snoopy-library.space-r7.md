---
title: Nagios XI RCE via Snoopy Library
author: space-r7
score: 1
topic_attacker_value: 5
topic_exploitability: 4
topic_disclosure_date: '2018-11-14T18:29:00'
created: '2019-06-28T15:23:21.981057'
revision_date: '2020-02-13T17:12:33.940384'
assessment_id: 958d14b2-a229-45a0-90c7-5491266ddd42
topic_id: 95f003c2-cc46-4a30-a9b8-806130b820a0
topic_short_id: 2HC0iysn3F
topic_slug: nagios-xi-rce-via-snoopy-library
akb_topic_url: https://attackerkb.com/topics/2HC0iysn3F/nagios-xi-rce-via-snoopy-library
akb_assessment_url: https://attackerkb.com/topics/2HC0iysn3F/nagios-xi-rce-via-snoopy-library#958d14b2-a229-45a0-90c7-5491266ddd42
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 3
  exploitability: 4
  urgent-to-patch: 5
  used-successfully: 1
---

# Nagios XI RCE via Snoopy Library

*Assessment by space-r7, archived from [AttackerKB](https://attackerkb.com/topics/2HC0iysn3F/nagios-xi-rce-via-snoopy-library#958d14b2-a229-45a0-90c7-5491266ddd42).*

---

If this vulnerability is found in the wild, then it's likely that the target is vulnerable to CVE-2018-15710 as well. An attacker can get unauthenticated root access to a target given that it is vulnerable to both vulnerabilities, which means it is incredibly important to get this patched. A module now exists for this vulnerability, which further eases the process of exploitation.
