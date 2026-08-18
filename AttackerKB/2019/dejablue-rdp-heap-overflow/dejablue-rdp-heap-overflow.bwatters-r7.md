---
title: DejaBlue, RDP Heap Overflow
author: bwatters-r7
score: 4
topic_attacker_value: 4.714285714285714
topic_exploitability: 3
topic_disclosure_date: '2019-08-14T21:15:00'
created: '2019-08-22T22:14:31.960792'
revision_date: '2020-02-21T17:47:00.736404'
assessment_id: d653ceea-6bd9-47b2-b253-884207a33525
topic_id: 3c6d4a84-b8ee-47a2-a1e9-388f5f32ad27
topic_short_id: 71QrpupdZO
topic_slug: dejablue-rdp-heap-overflow
akb_topic_url: https://attackerkb.com/topics/71QrpupdZO/dejablue-rdp-heap-overflow
akb_assessment_url: https://attackerkb.com/topics/71QrpupdZO/dejablue-rdp-heap-overflow#d653ceea-6bd9-47b2-b253-884207a33525
author_ratings:
  attacker-value: 4
  confidence-in-ratings: 4
  effort-to-develop-exploit: 5
  exploitability: 2
  urgent-to-patch: 5
  used-successfully: 1
---

# DejaBlue, RDP Heap Overflow

*Assessment by bwatters-r7, archived from [AttackerKB](https://attackerkb.com/topics/71QrpupdZO/dejablue-rdp-heap-overflow#d653ceea-6bd9-47b2-b253-884207a33525).*

---

This vulnerability was discovered while researchers audited the RDP code from the previous vulnerability, Bluekeep.  This vulnerability is likely going to be worse than Bluekeep, as it targets more modern operating systems.  The saving grace with Dejablue, as with Bluekeep and even Eternalblue is the complexity of turning the vulnerability into a reliable exploit, as the attacker must successfully trigger the vulnerability, write to kernel memory and to user memory, then execute the code in kernel memory to locate and execute the code in user memory.  Without question this is in the ability of nation states and probably even organized crime, but until a public version is released, this will be treated as a zero day by those attackers that posses it.  I would be surprised to see a public version of this that works reliably across Windows kernel 10 releases for at least another six to eight weeks (October 2019).
