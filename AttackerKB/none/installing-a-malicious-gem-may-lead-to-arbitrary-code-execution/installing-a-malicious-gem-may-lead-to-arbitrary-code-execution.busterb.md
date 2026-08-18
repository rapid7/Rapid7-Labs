---
title: Installing a malicious gem may lead to arbitrary code execution
author: busterb
score: 1
topic_attacker_value: 1
topic_exploitability: 3
created: '2019-05-09T17:57:42.669969'
revision_date: '2020-03-15T04:22:22.595044'
assessment_id: 16c6caaf-a53f-42df-88c9-875af94f3161
topic_id: b2ebbf0e-24e2-4432-8e53-7e8a540d8917
topic_short_id: 7lNzC8sTL1
topic_slug: installing-a-malicious-gem-may-lead-to-arbitrary-code-execution
akb_topic_url: https://attackerkb.com/topics/7lNzC8sTL1/installing-a-malicious-gem-may-lead-to-arbitrary-code-execution
akb_assessment_url: https://attackerkb.com/topics/7lNzC8sTL1/installing-a-malicious-gem-may-lead-to-arbitrary-code-execution#16c6caaf-a53f-42df-88c9-875af94f3161
author_ratings:
  attacker-value: 1
  confidence-in-ratings: 4
  effort-to-develop-exploit: 1
  exploitability: 3
  urgent-to-patch: 2
---

# Installing a malicious gem may lead to arbitrary code execution

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/7lNzC8sTL1/installing-a-malicious-gem-may-lead-to-arbitrary-code-execution#16c6caaf-a53f-42df-88c9-875af94f3161).*

---

Rubygems has a vulnerability that allows for arbitrary code execution while a gem is being installed. However, it's unclear how this is any worse than either using the malicious gem itself, or using the ability of gems to compile and execute arbitrary build instructions in the first place. It is interesting to be able to name a gem a particular way to create code execution. But you have to convince someone to install your gem in the first place. I presume that rubygems.org now prevents malicious gems from being published, but it would be interesting to see.
