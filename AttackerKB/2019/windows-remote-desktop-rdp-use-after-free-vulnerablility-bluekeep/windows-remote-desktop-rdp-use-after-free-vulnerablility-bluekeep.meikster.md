---
title: Windows Remote Desktop (RDP) Use-after-free vulnerablility, "Bluekeep"
author: meikster
score: 4
topic_attacker_value: 4.5
topic_exploitability: 2.2
topic_disclosure_date: '2019-05-16T19:29:00'
created: '2020-07-21T15:50:40.425219'
revision_date: '2020-07-28T23:12:39.913739'
assessment_id: 65a3530b-ccff-41be-ae7b-474a36ea1ee1
topic_id: 131226a6-a1e9-48a1-a5d0-ac94baf8dfd2
topic_short_id: huQasjoVMS
topic_slug: windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep
akb_topic_url: https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep
akb_assessment_url: https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep#65a3530b-ccff-41be-ae7b-474a36ea1ee1
author_ratings:
  attacker-value: 2
  exploitability: 1
  tags:
  - common_enterprise
  - high_privilege_access
  - pre_auth
  - obscure_configuration
---

# Windows Remote Desktop (RDP) Use-after-free vulnerablility, "Bluekeep"

*Assessment by meikster, archived from [AttackerKB](https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep#65a3530b-ccff-41be-ae7b-474a36ea1ee1).*

---

This vulnerability may seem very useful, it is probably as interesting as other RCEs affecting Microsoft Windows OSes, however public exploits rely on the existence of a registry key (fDisableCam) not being present by default (it has to be manually created) thus not found in enterprise networks.
