---
title: Oracle Java JRE AES Intrinsics Remote Denial of Service
author: jcran
score: 3
topic_attacker_value: 3
topic_exploitability: 5
topic_disclosure_date: '2015-07-16T11:00:00'
created: '2019-11-14T21:43:37.804549'
revision_date: '2020-05-29T14:51:13.725458'
assessment_id: 3e27fc54-7123-40fb-ae22-0f9def5a5bcb
topic_id: b9f2cfed-c0a1-431f-aeb0-dfa8b1ef82cf
topic_short_id: BhsMnU8Lca
topic_slug: oracle-java-jre-aes-intrinsics-remote-denial-of-service
akb_topic_url: https://attackerkb.com/topics/BhsMnU8Lca/oracle-java-jre-aes-intrinsics-remote-denial-of-service
akb_assessment_url: https://attackerkb.com/topics/BhsMnU8Lca/oracle-java-jre-aes-intrinsics-remote-denial-of-service#3e27fc54-7123-40fb-ae22-0f9def5a5bcb
author_ratings:
  attacker-value: 3
  confidence-in-ratings: 5
  effort-to-develop-exploit: 1
  exploitability: 5
  mitigation-strength: 3
  reliability: 5
  stability: 5
  urgent-to-patch: 5
  used-successfully: 5
---

# Oracle Java JRE AES Intrinsics Remote Denial of Service

*Assessment by jcran, archived from [AttackerKB](https://attackerkb.com/topics/BhsMnU8Lca/oracle-java-jre-aes-intrinsics-remote-denial-of-service#3e27fc54-7123-40fb-ae22-0f9def5a5bcb).*

---

Causes a hard crash for the web application server (for example, Tomcat) which directly handles web requests by simply posting 4097 characters to an affected server using the AES GCM cipher (where that server has the requisite CPU extensions enabled, which is most modern processors). Super easy to exploit; can just use curl.

See the blog post I wrote about it:
https://blog.rapid7.com/2015/07/16/r7-2015-09-oracle-java-jre-aes-intrinsics-remote-denial-of-service-cve-2015-2659/
