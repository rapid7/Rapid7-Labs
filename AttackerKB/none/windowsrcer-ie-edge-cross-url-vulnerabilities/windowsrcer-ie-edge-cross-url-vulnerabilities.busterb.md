---
title: Windowsrcer IE/Edge Cross-URL vulnerabilities
author: busterb
score: 4
topic_attacker_value: 3
topic_exploitability: 4
created: '2019-08-21T16:31:24.176821'
revision_date: '2020-04-26T23:02:11.020714'
assessment_id: 81ae9e60-7057-4880-8bca-c9b493ee32e1
topic_id: 7962c6db-020f-496c-9ead-77f2fb991724
topic_short_id: 25OoYixpsD
topic_slug: windowsrcer-ie-edge-cross-url-vulnerabilities
akb_topic_url: https://attackerkb.com/topics/25OoYixpsD/windowsrcer-ie-edge-cross-url-vulnerabilities
akb_assessment_url: https://attackerkb.com/topics/25OoYixpsD/windowsrcer-ie-edge-cross-url-vulnerabilities#81ae9e60-7057-4880-8bca-c9b493ee32e1
author_ratings:
  attacker-value: 3
  confidence-in-ratings: 3
  effort-to-develop-exploit: 1
  exploitability: 4
  urgent-to-patch: 3
  used-successfully: 5
---

# Windowsrcer IE/Edge Cross-URL vulnerabilities

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/25OoYixpsD/windowsrcer-ie-edge-cross-url-vulnerabilities#81ae9e60-7057-4880-8bca-c9b493ee32e1).*

---

A SOP bug requires the attacker to inject a resource into one domain, and be listening on another. Such a vulnerability would need to be combined with a web application vulnerability like XSS, and would be less useful from a standalone PoV as something like a Metasploit module. But with the right target audience and web application, this is a nice primitive.
