---
title: DNS over HTTPS
author: busterb
score: 3
topic_attacker_value: 5
topic_exploitability: 0
created: '2019-09-27T11:20:20.521074'
revision_date: '2020-02-21T22:32:40.55696'
assessment_id: 815871f3-d755-4431-9f2d-af5204cda65e
topic_id: 5dd41e84-590e-4922-8227-1abb31df44bb
topic_short_id: C4frGeNrZ6
topic_slug: dns-over-https
akb_topic_url: https://attackerkb.com/topics/C4frGeNrZ6/dns-over-https
akb_assessment_url: https://attackerkb.com/topics/C4frGeNrZ6/dns-over-https#815871f3-d755-4431-9f2d-af5204cda65e
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 5
---

# DNS over HTTPS

*Assessment by busterb, archived from [AttackerKB](https://attackerkb.com/topics/C4frGeNrZ6/dns-over-https#815871f3-d755-4431-9f2d-af5204cda65e).*

---

DNS over HTTPS is good for individual network privacy: it circumvents filters, nobody can see what you're browsing passively. If I was in a hotel or public wifi, it's definitely what I would expect my browser to use! But, it's bad for aggregate user privacy as browsers are rolling it out by default with their own DNS providers. Now Cloudflare, Google, or one of a few big resolvers see what you're browsing actively (since there are few local recursive resolvers). On the other hand, the privacy ship with respect to the big providers has probably sailed anyway.

DoH provides more security guarantees than other DNS security solutions, e.g. DNSSec ensures authentication and integrity but not confidentiality. But it has similar limitations that prevent it from being usable as a system-wide resolver. Verifying certificates requires accurate time, so you have to fall back to regular DNS when setting time via NTP, for instance. There's no 'just encrypt' option with for DNS-over-HTTPS/TLS. So you have to accept sometimes it's still going to fail-open if other properties can't be met.

DoH is _probably_ great for not standing out in network traffic: I can lookup domains without being noticed, and malware is beginning to use it as well, Since it's not easily distinguished in network traffic, adversaries can also avoid standing out. Wannacry was initially stopped by blackholing a domain over DNS. Identifying and sinkholing C2 domains now becomes harder. DNS has been a useful exfiltration and C2 technique for a while, since it exploits obscurity. DNS-over-HTTPS is even better, since it adds confidentiality over common infrastructure. There are some reference tools on this topic showing how this is accomplished.
