---
title: Inferring and hijacking VPN-tunneled TCP connections
author: busterb
score: 3
topic_attacker_value: 2
topic_exploitability: 0
created: '2019-12-07T14:42:53.565943'
revision_date: '2020-02-13T17:11:52.267935'
assessment_id: 6040e9fb-6446-407f-abba-d64cd84de31a
topic_id: 87bed4c4-074f-4154-8df7-b5ffd670b137
topic_short_id: t4SltvfKQy
topic_slug: inferring-and-hijacking-vpn-tunneled-tcp-connections
akb_topic_url: https://attackerkb.com/topics/t4SltvfKQy/inferring-and-hijacking-vpn-tunneled-tcp-connections
akb_assessment_url: https://attackerkb.com/topics/t4SltvfKQy/inferring-and-hijacking-vpn-tunneled-tcp-connections#6040e9fb-6446-407f-abba-d64cd84de31a
author_ratings:
  attacker-value: 2
  confidence-in-ratings: 3
  mitigation-strength: 1
  used-successfully: 1
---

# Inferring and hijacking VPN-tunneled TCP connections

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/t4SltvfKQy/inferring-and-hijacking-vpn-tunneled-tcp-connections#6040e9fb-6446-407f-abba-d64cd84de31a).*

---

The discussion here https://lwn.net/Articles/806546/ shows some of the problems fixing this generally, which really means disabling the weak host model as a mitigation. This is likely perfectly fine for single-ended hosts, which are likely the most vulnerable targets in the first place.
