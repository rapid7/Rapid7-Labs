---
title: Windows Remote Desktop (RDP) Use-after-free vulnerablility, "Bluekeep"
author: lvarela-r7
score: 3
topic_attacker_value: 4.5
topic_exploitability: 2.2
topic_disclosure_date: '2019-05-16T19:29:00'
created: '2020-04-16T14:00:29.190928'
revision_date: '2020-04-18T03:25:22.896726'
assessment_id: e9946464-0572-49d5-a7fd-08c7f4fca39d
topic_id: 131226a6-a1e9-48a1-a5d0-ac94baf8dfd2
topic_short_id: huQasjoVMS
topic_slug: windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep
akb_topic_url: https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep
akb_assessment_url: https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep#e9946464-0572-49d5-a7fd-08c7f4fca39d
author_ratings:
  tags:
  - common_enterprise
  - pre_auth
---

# Windows Remote Desktop (RDP) Use-after-free vulnerablility, "Bluekeep"

*Assessment by lvarela-r7, archived from [AttackerKB](https://attackerkb.com/topics/huQasjoVMS/windows-remote-desktop-rdp-use-after-free-vulnerablility-bluekeep#e9946464-0572-49d5-a7fd-08c7f4fca39d).*

---

Some of the gotchas on patching this vuln: 
 - Not restarting the vulnerable asset, even after you apply the patch, keeps the asset vulnerable. Must restart.
 - There have been cases where even with the patch reported as being installed, files on disk were vulnerable, manually checking termdd.sys, the file is normally located at C:\Windows\System32\drivers and the version retrieved with this powershell command:

get-item -Path 'C:\Windows\System32\drivers\termdd.sys' | Format-List -Force
