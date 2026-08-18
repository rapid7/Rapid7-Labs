---
title: Unknown iOS Mail.App RCE ZecOps
author: todb-r7
score: 6
topic_attacker_value: 1
topic_exploitability: 1
created: '2020-04-22T17:12:14.773236'
revision_date: '2020-04-25T00:12:55.518219'
assessment_id: 36217e96-2a56-4f53-9ba4-7cf15b0e26bd
topic_id: f1080147-f670-4841-8bd9-6c5b9fc776da
topic_short_id: Nq31BcArpN
topic_slug: unknown-ios-mail-app-rce-zecops
akb_topic_url: https://attackerkb.com/topics/Nq31BcArpN/unknown-ios-mail-app-rce-zecops
akb_assessment_url: https://attackerkb.com/topics/Nq31BcArpN/unknown-ios-mail-app-rce-zecops#36217e96-2a56-4f53-9ba4-7cf15b0e26bd
author_ratings:
  attacker-value: 1
  exploitability: 1
  tags:
  - pre_auth
  - requires_interaction
  - no_useful_data
  - difficult_to_develop
---

# Unknown iOS Mail.App RCE ZecOps

*Assessment by todb-r7, archived from [AttackerKB](https://attackerkb.com/topics/Nq31BcArpN/unknown-ios-mail-app-rce-zecops#36217e96-2a56-4f53-9ba4-7cf15b0e26bd).*

---

**Update April 24, 2020**

Turns out, Apple and HD are both of the opinion that the vulnerability doesn't exist. See the reporting at Ars:

https://arstechnica.com/information-technology/2020/04/apple-disputes-report-of-non-click-ios-0day-under-exploit-for-two-years/

What's the lesson here? PoC||GTFO, and let the vendors do their jobs as part of coordinated vulnerability disclosure. Updating the high-value/low-value indicators here.

**Original Report Below**

It technically "requires user interaction" but that interaction is merely opening a malicious email. It doesn't sound like you need to click on anything.

According to the report, Apple has confirmed the existence, but we haven't seen a patch or a CVE or anything like that.

This is super-duper high value, IMO. Million dollar bug. Own any-ish iPhone, assuming they're using Mail.app, which most are (there are 3rd party email applications, like Gmail and Yahoo! Mail, but they are somewhat rare in the iPhone / iPad ecosystem).
