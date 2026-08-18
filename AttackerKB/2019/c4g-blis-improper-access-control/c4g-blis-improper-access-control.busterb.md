---
title: C4G BLIS Improper Access Control
author: busterb
score: 1
topic_attacker_value: 3
topic_exploitability: 5
topic_disclosure_date: '2019-11-06T19:15:00'
created: '2019-11-14T22:04:44.695486'
revision_date: '2020-02-13T17:11:56.095648'
assessment_id: 4681b1a9-b3ec-438c-b7f7-f114076d591c
topic_id: c7974b74-e51d-401d-aa60-f64ff97ee2f7
topic_short_id: eBMS2i2d54
topic_slug: c4g-blis-improper-access-control
akb_topic_url: https://attackerkb.com/topics/eBMS2i2d54/c4g-blis-improper-access-control
akb_assessment_url: https://attackerkb.com/topics/eBMS2i2d54/c4g-blis-improper-access-control#4681b1a9-b3ec-438c-b7f7-f114076d591c
author_ratings:
  attacker-value: 3
  confidence-in-ratings: 5
  effort-to-develop-exploit: 1
  exploitability: 5
  mitigation-strength: 3
  urgent-to-patch: 5
  used-successfully: 5
---

# C4G BLIS Improper Access Control

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/eBMS2i2d54/c4g-blis-improper-access-control#4681b1a9-b3ec-438c-b7f7-f114076d591c).*

---

Authentication bypass on medical software in general is a big utility to both an attacker and a liability for medical professionals using the software.

Where is may be less applicable in utility is simply in where it is used. The list of labs that do use this software is listed straight on the software's website which hopefully allowed them to communicate the importance of patching before this vulnerability was announced (and hopefully they applied additional compensating controls in the process): http://blis.cc.gatech.edu/index.php
