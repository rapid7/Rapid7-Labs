---
title: Windows Remote Desktop (RDP) Use-after-free vulnerablility, "Bluekeep"
author: kevthehermit
score: 6
topic_attacker_value: 4.5
topic_exploitability: 2.2
topic_disclosure_date: '2019-05-16T19:29:00'
created: '2020-02-22T22:52:11.064365'
revision_date: '2020-04-26T23:02:44.203161'
assessment_id: 6e52706e-dfa3-49d0-ba4d-f3b5b8772d04
topic_id: 131226a6-a1e9-48a1-a5d0-ac94baf8dfd2
topic_short_id: huQasjoVMS
topic_slug: windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep
akb_topic_url: https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep
akb_assessment_url: https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep#6e52706e-dfa3-49d0-ba4d-f3b5b8772d04
author_ratings:
  attacker-value: 4
  exploitability: 2
  tags:
  - common_enterprise
  - high_privilege_access
  - difficult_to_develop
---

# Windows Remote Desktop (RDP) Use-after-free vulnerablility, "Bluekeep"

*Assessment by kevthehermit, archived from [AttackerKB](https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep#6e52706e-dfa3-49d0-ba4d-f3b5b8772d04).*

---

Like some others have said, this requires an understanding of your targets Host devices in order to generate a reliable exploit. This involves identifying the Start address of the NonPageedPool and plugging this into the existing metasploit module. 

With a large number of cloud-based resources this is perhaps a little easier to exploit than enterprise desktops. 

An example against AWS hosted windows appliances works something like this.

- Spin up your own AWS Instance.
- Use Memory Dump tool like WinPMem to grab a memory image. 
- Transfer mem dump to a machine running the rekall memory forensics tool
- Run the `pools` plugin to get the address. 

This offset will work against any instance in this region started from that same base AMI. 

![alt text](https://pbs.twimg.com/media/ED4Yc6XWsAU-LXS?format=png&name=900x900 "https://twitter.com/KevTheHermit/status/1170399843841388549")
