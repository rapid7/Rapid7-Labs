---
title: Amnesia:33
author: ccondon-r7
score: 4
topic_attacker_value: 2
topic_exploitability: 0
created: '2020-12-08T21:05:04.560741'
revision_date: '2020-12-11T18:39:46.441556'
assessment_id: e8a4d3ce-0a88-4600-bba0-1830718a1c22
topic_id: d06e04ab-0ffe-4ce4-a29c-24bc05f6e804
topic_short_id: UBfm95fV8w
topic_slug: amnesia-33
akb_topic_url: https://attackerkb.com/topics/UBfm95fV8w/amnesia-33
akb_assessment_url: https://attackerkb.com/topics/UBfm95fV8w/amnesia-33#e8a4d3ce-0a88-4600-bba0-1830718a1c22
author_ratings:
  attacker-value: 2
---

# Amnesia:33

*Assessment by ccondon-r7, archived from [AttackerKB](https://attackerkb.com/topics/UBfm95fV8w/amnesia-33#e8a4d3ce-0a88-4600-bba0-1830718a1c22).*

---

Sorta relying here on the fact that memory corruption vulns are difficult to weaponize or even trigger reliably, and it sounds like there will be lots of different implementations of the vulnerable libraries, so uniform attack surface area is going to be scarce. Rapid7's IoT research lead noted as well that TCP stack issues like this may well require the attacker to be on same subnet, and it's unlikely that upstream routers would accept unexpected/malformed packets. There'll be lots of fragmented vendor advisories trickling out in bits, I'd expect. There may be more detail out on which to base assessments later this week.
