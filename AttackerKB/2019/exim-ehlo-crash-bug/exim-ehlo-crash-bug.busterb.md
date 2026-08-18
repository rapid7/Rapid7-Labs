---
title: Exim EHLO crash bug
author: busterb
score: 1
topic_attacker_value: 2.5
topic_exploitability: 3.5
topic_disclosure_date: '2019-09-27T21:15:00'
created: '2019-10-02T22:34:27.459775'
revision_date: '2020-02-13T17:12:02.060794'
assessment_id: 4b840b1e-6c28-4952-9401-156f04b52e91
topic_id: 862dfb64-ee07-4f1f-b5f3-8f2c3a560a5f
topic_short_id: T6aghc4yib
topic_slug: exim-ehlo-crash-bug
akb_topic_url: https://attackerkb.com/topics/T6aghc4yib/exim-ehlo-crash-bug
akb_assessment_url: https://attackerkb.com/topics/T6aghc4yib/exim-ehlo-crash-bug#4b840b1e-6c28-4952-9401-156f04b52e91
author_ratings:
  attacker-value: 2
  confidence-in-ratings: 5
  effort-to-develop-exploit: 4
  exploitability: 4
  urgent-to-patch: 5
  used-successfully: 5
---

# Exim EHLO crash bug

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/T6aghc4yib/exim-ehlo-crash-bug#4b840b1e-6c28-4952-9401-156f04b52e91).*

---

Implementing a crash for this is pretty easy. Implementing an exploit may be tricky given the diversity of heap configurations, though if you targeted one distro or container it's probably easier.

Note, this vulnerability was also fixed before it was reported as a result of deeper analysis of user-controlled variables in Exim as a whole. Future releases of Exim may be much harder to exploit as a result of this general effort. See this note from Exim maintainer 'Comet' on areas they need help with in the future:  https://lwn.net/Articles/801265/
