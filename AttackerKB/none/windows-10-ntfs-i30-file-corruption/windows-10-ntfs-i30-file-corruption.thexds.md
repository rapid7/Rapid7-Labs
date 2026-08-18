---
title: Windows 10 NTFS $i30 File Corruption
author: TheXDS
score: 2
topic_attacker_value: 1
topic_exploitability: 5
created: '2021-02-01T03:38:19.200598'
revision_date: '2021-02-09T16:40:55.505507'
assessment_id: 37dd4a1b-fd8c-4a3e-adef-f2dc864e68ff
topic_id: 7d2aa7fe-2311-4fbe-b5e4-130d2602f980
topic_short_id: PY30JMkzjw
topic_slug: windows-10-ntfs-i30-file-corruption
akb_topic_url: https://attackerkb.com/topics/PY30JMkzjw/windows-10-ntfs-i30-file-corruption
akb_assessment_url: https://attackerkb.com/topics/PY30JMkzjw/windows-10-ntfs-i30-file-corruption#37dd4a1b-fd8c-4a3e-adef-f2dc864e68ff
author_ratings:
  attacker-value: 1
  exploitability: 5
  mitre-tactics: Impact
---

# Windows 10 NTFS $i30 File Corruption

*Assessment by TheXDS, archived from [AttackerKB](https://attackerkb.com/topics/PY30JMkzjw/windows-10-ntfs-i30-file-corruption#37dd4a1b-fd8c-4a3e-adef-f2dc864e68ff).*

---

This is a grave oversight of the way the NTFS driver handles path access to special directory attributes. Any kind of file access that could be performed by Windows where it might need to read a path trying to access the :$i30:$Bitmap attribute on a directory from the user's context will cause the corruption of the accessed directory. If performed over the root directory, the entire drive will be affected.

Simple stuff like crafting a .url file with the path will cause the system to become corrupted. Please, avoid extracting any untrusted .URL/.LNK files from any files you download from the internet.
