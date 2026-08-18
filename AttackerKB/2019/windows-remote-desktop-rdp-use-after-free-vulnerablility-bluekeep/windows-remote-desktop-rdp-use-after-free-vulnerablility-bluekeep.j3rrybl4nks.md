---
title: Windows Remote Desktop (RDP) Use-after-free vulnerablility, "Bluekeep"
author: J3rryBl4nks
score: 3
topic_attacker_value: 4.5
topic_exploitability: 2.2
topic_disclosure_date: '2019-05-16T19:29:00'
created: '2020-03-03T16:18:02.422157'
revision_date: '2020-04-19T03:04:44.325342'
assessment_id: b8769191-423f-4dc4-98c8-210a1ddab3ef
topic_id: 131226a6-a1e9-48a1-a5d0-ac94baf8dfd2
topic_short_id: huQasjoVMS
topic_slug: windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep
akb_topic_url: https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep
akb_assessment_url: https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep#b8769191-423f-4dc4-98c8-210a1ddab3ef
author_ratings:
  attacker-value: 5
  exploitability: 3
  tags:
  - high_privilege_access
  - common_enterprise
  - default_configuration
---

# Windows Remote Desktop (RDP) Use-after-free vulnerablility, "Bluekeep"

*Assessment by J3rryBl4nks, archived from [AttackerKB](https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep#b8769191-423f-4dc4-98c8-210a1ddab3ef).*

---

Due to public exploits being flaky and sometimes resulting in a Blue Screen on the victim, this exploit is still somewhat difficult to always replicate. If you have paid tools that have better versions of the exploit, it's more reliable.

The fact that an exploit is included in newer versions of metasploit massively lowers the bar for being able to exploit this vulnerability.

The damage potential is astronomical as there are so many machines that expose RDP to the internet.
