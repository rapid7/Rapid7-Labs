---
title: 'OneDrive DLL hijack privilege escalation '
author: SarahMarsh67-a11y
score: 1
topic_attacker_value: 2
topic_exploitability: 5
created: '2026-01-21T11:31:44.547941'
revision_date: '2026-01-21T11:31:44.54758'
assessment_id: 4005a3f2-eb8e-4aa5-8832-91761382bc9d
topic_id: fc9d50fc-c6f5-4a1a-a859-f3e33911c541
topic_short_id: Oj1Wwfi57A
topic_slug: onedrive-dll-hijack-privilege-escalation
akb_topic_url: https://attackerkb.com/topics/Oj1Wwfi57A/onedrive-dll-hijack-privilege-escalation
akb_assessment_url: https://attackerkb.com/topics/Oj1Wwfi57A/onedrive-dll-hijack-privilege-escalation#4005a3f2-eb8e-4aa5-8832-91761382bc9d
author_ratings:
  mitre-tactics: Initial Access
---

# OneDrive DLL hijack privilege escalation 

*Assessment by SarahMarsh67-a11y, archived from [AttackerKB](https://attackerkb.com/topics/Oj1Wwfi57A/onedrive-dll-hijack-privilege-escalation#4005a3f2-eb8e-4aa5-8832-91761382bc9d).*

---

This vulnerability allows scripting commands to load from SharePoint servers and one drive, when signing into OneDrive the malicious software will load onto the computer during sync operations and land as a vault executable. This vulnerability allows modifying of files and photos and is the attack entry point for creating  a shadow account which then allows authorization for multiple sign ins and unauthorized access to bookmarks, history and credentials. They create scripts and save their commands and scripts inside of SharePoint and use graph connections to control AI services, which they can’t control remotely altering Chat behavior and exhilarating data from the AI services. These shadow accounts tie to malicious fake login pages where they use fake icon packs for icon smuggling and they use these packs on the computer to replace legitimate applications to trick the user into clicking, which send the user to the fake website where they continue to steal more resources and credentials. These APT threat actors use this to create profiles of their intended targets and to maintain persistent access with every device and network they get access to. They replace the files with executable content or delete and steal data. I have seen them use Cortana and the executable help.exe to use feedback hub, and for fake setup during reinstalling feature. They use the OneDrive to perform most of their operations especially using the sync feature to load their malicious code. These threat actors are the most sophisticated coders there are, it’s taken years of work to get them removed uncovering every layer that they have covered. They use the vault in one drive to steal the data then replace it with a RAT Trojan to execute when the user opens the vault. 
