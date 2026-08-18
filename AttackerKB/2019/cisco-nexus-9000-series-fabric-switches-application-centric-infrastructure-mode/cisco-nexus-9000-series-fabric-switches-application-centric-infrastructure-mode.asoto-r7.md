---
title: Cisco Nexus 9000 Series Fabric Switches Application Centric Infrastructure Mode Default SSH Key Vulnerability
author: asoto-r7
score: 0
topic_attacker_value: 5
topic_exploitability: 1
topic_disclosure_date: '2019-05-03T17:29:00'
created: '2019-07-24T20:37:14.08226'
revision_date: '2020-04-28T21:34:02.043826'
assessment_id: fefa39d0-1848-46a3-b924-b43bece29d1b
topic_id: a29f033f-47f8-4658-b470-4a3f541e9175
topic_short_id: KmiVPM0LeJ
topic_slug: cisco-nexus-9000-series-fabric-switches-application-centric-infrastructure-mode-default-ssh-key-vulnerability
akb_topic_url: https://attackerkb.com/topics/KmiVPM0LeJ/cisco-nexus-9000-series-fabric-switches-application-centric-infrastructure-mode-default-ssh-key-vulnerability
akb_assessment_url: https://attackerkb.com/topics/KmiVPM0LeJ/cisco-nexus-9000-series-fabric-switches-application-centric-infrastructure-mode-default-ssh-key-vulnerability#fefa39d0-1848-46a3-b924-b43bece29d1b
---

# Cisco Nexus 9000 Series Fabric Switches Application Centric Infrastructure Mode Default SSH Key Vulnerability

*Assessment by asoto-r7, archived from [AttackerKB](https://attackerkb.com/topics/KmiVPM0LeJ/cisco-nexus-9000-series-fabric-switches-application-centric-infrastructure-mode-default-ssh-key-vulnerability#fefa39d0-1848-46a3-b924-b43bece29d1b).*

---

We still haven't seen a PoC for this, likely because these switches are expensive and the firmware is paywalled.  Further, the advisory returns a 503 right now, so here's the archive.org link: https://web.archive.org/web/20190521004255/https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-nexus9k-sshkey

It's interesting that this needs to be exploited over IPv6.  However, it's likely that a foothold in the target network or a tunnel through a compromised machine would allow access to this switch.  These switches are used as part of SDN-based datacenters, so getting a foothold on a compromised server might allow an attacker to pivot to another subnet, VLAN, or cloud.
