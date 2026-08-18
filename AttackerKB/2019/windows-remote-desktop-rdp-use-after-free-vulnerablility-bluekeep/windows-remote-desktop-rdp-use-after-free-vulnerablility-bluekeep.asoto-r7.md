---
title: Windows Remote Desktop (RDP) Use-after-free vulnerablility, "Bluekeep"
author: asoto-r7
score: 4
topic_attacker_value: 4.5
topic_exploitability: 2.2
topic_disclosure_date: '2019-05-16T19:29:00'
created: '2019-05-14T20:16:36.115684'
revision_date: '2020-04-19T03:04:02.821157'
assessment_id: 1975e308-e0fe-495a-bfaf-31c3c6bda1aa
topic_id: 131226a6-a1e9-48a1-a5d0-ac94baf8dfd2
topic_short_id: huQasjoVMS
topic_slug: windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep
akb_topic_url: https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep
akb_assessment_url: https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep#1975e308-e0fe-495a-bfaf-31c3c6bda1aa
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 3
  effort-to-develop-exploit: 5
  exploitability: 1
  urgent-to-patch: 5
  used-successfully: 1
---

# Windows Remote Desktop (RDP) Use-after-free vulnerablility, "Bluekeep"

*Assessment by asoto-r7, archived from [AttackerKB](https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep#1975e308-e0fe-495a-bfaf-31c3c6bda1aa).*

---

Watch this one for details.  In the meantime, if you can't patch, then block TCP/3389 (or whatever port you might be mapping RDP to), enable Network Level Authentication (NLA), or disable RDP.

This exploit is critical.  RDP is ubiquitous in corporate settings, which are the most likely to have older Operating Systems deployed.  That issue is complicated by the general reasoning that most older Operating systems are there to support legacy equipment and are less likely to receive automated patching.

EDIT (24-July-2019): Welp, we've heard lots of researchers say they're privately holding onto PoCs, but now PoCs and details are starting to surface.  It won't be long until this one is easily weaponized, and I'm willing to bet it's being used in the wild, if only in selected cases.
