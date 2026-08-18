---
title: 'OneDrive DLL hijack privilege escalation '
author: bwatters-r7
score: 3
topic_attacker_value: 2
topic_exploitability: 5
created: '2020-07-31T21:04:58.040629'
revision_date: '2020-09-30T16:40:11.182107'
assessment_id: f10a7142-eadb-4f08-a3f5-4ee3ee6f7605
topic_id: fc9d50fc-c6f5-4a1a-a859-f3e33911c541
topic_short_id: Oj1Wwfi57A
topic_slug: onedrive-dll-hijack-privilege-escalation
akb_topic_url: https://attackerkb.com/topics/Oj1Wwfi57A/onedrive-dll-hijack-privilege-escalation
akb_assessment_url: https://attackerkb.com/topics/Oj1Wwfi57A/onedrive-dll-hijack-privilege-escalation#f10a7142-eadb-4f08-a3f5-4ee3ee6f7605
author_ratings:
  attacker-value: 2
  exploitability: 5
---

# OneDrive DLL hijack privilege escalation 

*Assessment by bwatters-r7, archived from [AttackerKB](https://attackerkb.com/topics/Oj1Wwfi57A/onedrive-dll-hijack-privilege-escalation#f10a7142-eadb-4f08-a3f5-4ee3ee6f7605).*

---

EDIT:  This is not a privilege escalation per se.  This overwrites the dll and gains injection, but it relies on a second user with greater privileges to log in and kick off OneDrive.


This exploit was not granted a CVE, but it was patched by an automated patch rollout.  Microsoft denied the CVE as the update will happen automatically (see [here]{https://labs.redyops.com/index.php/2020/04/27/onedrive-privilege-of-escalation/} for more information).
The exploit is a very simple dll hijacking vulnerability in the OneDrive executable.  The onedrive executable will attempt to load a specific (and often non-existant) dll if a specific config file is present.
Specifically, Onedrive will load the dll `C:\Qt\Qt-5.11.1\qml\QtQuick.2.7\qtquick2plugin.dll` if the file `C:\Qt\Qt-5.11.1\qml\QtQuick.2.7\qmldir` with the following contents:
```
module QtQuick 
plugin qtquick2plugin 
classname QtQuick2Plugin 
typeinfo plugins.qmltypes 
designersupported
```
Onedrive will load this dll into its trusted process if a user interacts with OneDrive.

This exploit is already patched and has a published Defender signature, but the service does not have to be in-use or logged in for the exploit to work.  In my testing, an unpatched Windows 10x64 1903 VM was vulnerable in the default configuration (apart from disabling defender).

Because this exploit is patched, automatically updated, and already has a signature for it, it will likely have a short shelf life in most locations, but it does provide an opportunity for exploitation of air-gapped or other system that does not talk to the internet.
