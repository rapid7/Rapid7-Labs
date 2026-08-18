---
title: Nuuo Central Management Server Authenticated Arbitrary File Upload
author: jrobles-r7
score: 1
topic_attacker_value: 3
topic_exploitability: 2
topic_disclosure_date: '2018-11-27T20:29:00'
created: '2019-05-09T17:57:41.485165'
revision_date: '2020-03-15T04:22:22.595044'
assessment_id: cd93475e-4b3b-482e-8c72-5c2acdf45d64
topic_id: 09df980f-c82e-4104-8dc0-77722281be1c
topic_short_id: jqjPoYIIO5
topic_slug: nuuo-central-management-server-authenticated-arbitrary-file-upload
akb_topic_url: https://attackerkb.com/topics/jqjPoYIIO5/nuuo-central-management-server-authenticated-arbitrary-file-upload
akb_assessment_url: https://attackerkb.com/topics/jqjPoYIIO5/nuuo-central-management-server-authenticated-arbitrary-file-upload#cd93475e-4b3b-482e-8c72-5c2acdf45d64
author_ratings:
  attacker-value: 3
  confidence-in-ratings: 3
  exploitability: 2
  offensive-application: not sure
  urgent-to-patch: 4
---

# Nuuo Central Management Server Authenticated Arbitrary File Upload

*Assessment by jrobles-r7, archived from [AttackerKB](https://attackerkb.com/topics/jqjPoYIIO5/nuuo-central-management-server-authenticated-arbitrary-file-upload#cd93475e-4b3b-482e-8c72-5c2acdf45d64).*

---

## Details

Details from [module documentation](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/nuuo/nuuo_cms_fu.md) in Metasploit.

The COMMITCONFIG verb is used by a CMS client to upload and modify the configuration of the CMS Server. An example is below:

```
COMMITCONFIG NUCM/1.0
User-Session-No: <session-number>
Filename: <filename>
FileType: <number>
Content-Lenght: <file-length>

<FILE_DATA>
```

The vulnerability is in the "FileName" parameter, which accepts directory traversal (..\\..\\) characters. Therefore, this function can be abused to overwrite any files in the installation drive of CMS Server.

This vulnerability is exploitable in CMS versions up to and including v2.4.

This module will either use a provided session number (which can be guessed with an auxiliary module) or attempt to login using a provided username and password - it will also try the default credentials if nothing is provided.
