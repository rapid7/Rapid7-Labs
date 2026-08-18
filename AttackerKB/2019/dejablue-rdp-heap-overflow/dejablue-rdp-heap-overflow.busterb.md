---
title: DejaBlue, RDP Heap Overflow
author: busterb
score: 4
topic_attacker_value: 4.714285714285714
topic_exploitability: 3
topic_disclosure_date: '2019-08-14T21:15:00'
created: '2019-08-13T17:48:20.669307'
revision_date: '2020-02-21T17:46:59.052995'
assessment_id: c15dba18-b61d-4272-b44b-a6935ca5a6f5
topic_id: 3c6d4a84-b8ee-47a2-a1e9-388f5f32ad27
topic_short_id: 71QrpupdZO
topic_slug: dejablue-rdp-heap-overflow
akb_topic_url: https://attackerkb.com/topics/71QrpupdZO/dejablue-rdp-heap-overflow
akb_assessment_url: https://attackerkb.com/topics/71QrpupdZO/dejablue-rdp-heap-overflow#c15dba18-b61d-4272-b44b-a6935ca5a6f5
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 4
  urgent-to-patch: 5
  used-successfully: 1
---

# DejaBlue, RDP Heap Overflow

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/71QrpupdZO/dejablue-rdp-heap-overflow#c15dba18-b61d-4272-b44b-a6935ca5a6f5).*

---

Affects every version of Windows from Windows 7 to Windows 10.  A DVC, or Dynamic Virtual Channel, packet needs to be sent with a specially-crafted uncompressed field field value larger than an integer, causing an overflow, according to MalwareTech's writeup here: https://www.malwaretech.com/2019/08/dejablue-analyzing-a-rdp-heap-overflow.html
