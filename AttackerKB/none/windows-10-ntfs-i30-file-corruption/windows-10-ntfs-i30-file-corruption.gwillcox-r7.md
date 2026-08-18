---
title: Windows 10 NTFS $i30 File Corruption
author: gwillcox-r7
score: 3
topic_attacker_value: 1
topic_exploitability: 5
created: '2021-01-15T18:01:53.726906'
revision_date: '2021-02-03T19:49:19.130642'
assessment_id: 00bbb0f5-7ea4-4a27-bd23-f627c366cb83
topic_id: 7d2aa7fe-2311-4fbe-b5e4-130d2602f980
topic_short_id: PY30JMkzjw
topic_slug: windows-10-ntfs-i30-file-corruption
akb_topic_url: https://attackerkb.com/topics/PY30JMkzjw/windows-10-ntfs-i30-file-corruption
akb_assessment_url: https://attackerkb.com/topics/PY30JMkzjw/windows-10-ntfs-i30-file-corruption#00bbb0f5-7ea4-4a27-bd23-f627c366cb83
author_ratings:
  attacker-value: 1
  exploitability: 5
---

# Windows 10 NTFS $i30 File Corruption

*Assessment by gwillcox-r7, archived from [AttackerKB](https://attackerkb.com/topics/PY30JMkzjw/windows-10-ntfs-i30-file-corruption#00bbb0f5-7ea4-4a27-bd23-f627c366cb83).*

---

There appears to be a lot of hype at the moment surrounding this vulnerability given the recent Tweets from @jonaslyk on Twitter at https://twitter.com/jonasLyk/status/1347900440000811010 as well as the follow up article from BleepingComputer at https://www.bleepingcomputer.com/news/security/windows-10-bug-corrupts-your-hard-drive-on-seeing-this-files-icon/.

Whilst this bug is made out to sound like a catastrophic disaster in Windows that could result in data loss should a user browse to a malicious file path containing the string `C:/:$i30:` followed by a file name such as `C:/:$i30:$bitmap`, the reality is that, at least in my tests, this is not the case. In fact during my tests I found the following:

1. The disk is not actually corrupted. If you try to access files on the disk, you can still interact with them and do things normally without any issues. Windows just somehow thinks that the disk is corrupted, even though it isn't.
2. Rebooting will case Windows to check the disk and try to repair it. If you skip this disk check, Windows will still think that the disk is corrupted, even though your computer will work fine. You will have to run a disk check by going to File Explorer, right clicking on the affected drive such as `C:\`, clicking `Properties`, then the `Tools` tab, and click `Check` under the `Error Checking` section. This will then require the computer to reboot, which should be pretty quick (a few seconds in my case for a clean Windows 10 20H2 VM), after which Windows will have self corrected itself and will no longer assume the disk is corrupt.
3. You can trigger this remotely via handlers such as the `file://` handler so this could be exploited remotely by embedding a HTML link into a web page that invokes the `file://` handler on `C:/:$i30:$bitmap`. This will cause an immediate warning to display on the user's computer that the drive is corrupted, which may be enough to convince them to reboot. Alternatively the user could just continue to use the computer and ignore the warning with no side effects.

So in conclusion this seems more like a logic/state error bug where Windows is tricked into thinking a drive is corrupted when it is not than any real serious issue, at least from the results that I am seeing in a VM. I don't know if physical computers would be any different as I haven't tested it on a physical machine, but I do not believe there would be any reason to believe the results would be different.
