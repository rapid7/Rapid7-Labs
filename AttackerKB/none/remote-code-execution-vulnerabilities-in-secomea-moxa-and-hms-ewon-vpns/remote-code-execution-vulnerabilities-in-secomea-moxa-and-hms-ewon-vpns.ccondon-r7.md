---
title: Remote Code Execution Vulnerabilities in Secomea, Moxa, and HMS eWon VPNs
author: ccondon-r7
score: 3
topic_attacker_value: 5
topic_exploitability: 0
created: '2020-07-30T03:06:49.83275'
revision_date: '2020-08-05T20:47:22.95043'
assessment_id: 3b8dfca6-5749-4bf8-bd03-d091ed41a576
topic_id: 10ea1efd-6c95-4b64-9784-a817b1822004
topic_short_id: lRQRKyIkBR
topic_slug: remote-code-execution-vulnerabilities-in-secomea-moxa-and-hms-ewon-vpns
akb_topic_url: https://attackerkb.com/topics/lRQRKyIkBR/remote-code-execution-vulnerabilities-in-secomea-moxa-and-hms-ewon-vpns
akb_assessment_url: https://attackerkb.com/topics/lRQRKyIkBR/remote-code-execution-vulnerabilities-in-secomea-moxa-and-hms-ewon-vpns#3b8dfca6-5749-4bf8-bd03-d091ed41a576
author_ratings:
  attacker-value: 5
  tags:
  - difficult_to_patch
  - high_privilege_access
  - pre_auth
---

# Remote Code Execution Vulnerabilities in Secomea, Moxa, and HMS eWon VPNs

*Assessment by ccondon-r7, archived from [AttackerKB](https://attackerkb.com/topics/lRQRKyIkBR/remote-code-execution-vulnerabilities-in-secomea-moxa-and-hms-ewon-vpns#3b8dfca6-5749-4bf8-bd03-d091ed41a576).*

---

The exposed target population may be comparatively low to, say, the whole of the internet, but [Rapid7 Labs has noted](https://blog.rapid7.com/2020/07/29/remote-code-execution-risks-in-secomea-moxa-and-hms-ewon-ics-vpn-vulnerabilities-what-you-need-to-know/)—rightly so—that a couple thousand exposed gateways is still a pretty concerning state of affairs when those gateways are protecting *industrial control systems*. Pre-authenticated RCE in VPN products guarding ICS/OT networks during a pandemic is, as the kids say, bad news bears—and that's not to make light, because this ain't light. The good news is that there are patches out for all these vulns, even though the downtime required to patch and verify effectively might be nothing to sneeze at. Longer [analysis and recommendations by smart people here](https://attackerkb.com/topics/lRQRKyIkBR/remote-code-execution-vulnerabilities-in-secomea-moxa-and-hms-ewon-vpns?#rapid7-analysis) [archive](https://github.com/rapid7/Rapid7-Labs/blob/main/AttackerKB/none/remote-code-execution-vulnerabilities-in-secomea-moxa-and-hms-ewon-vpns/README.md).

Researchers from around Rapid7's world (and likely others, too!) have said today that there is likely lower-hanging fruit that will be surfaced in the coming days, particularly around nerve-wracking findings such as exposed Telnet administration ports. There's a lot of well-justified attention on this grouping of vulns, and with that attention comes increased focus on attack opportunities in general...and the stuff we see clogging up our security noise machines won't be the only stuff well-resourced attackers are paying attention to. Patch as soon as possible (and yep, easier said than done). 
