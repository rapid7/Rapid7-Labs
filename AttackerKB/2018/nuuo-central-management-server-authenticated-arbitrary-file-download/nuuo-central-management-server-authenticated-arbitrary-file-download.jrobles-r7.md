---
title: Nuuo Central Management Server Authenticated Arbitrary File Download
author: jrobles-r7
score: 0
topic_attacker_value: 3
topic_exploitability: 2
topic_disclosure_date: '2018-11-27T20:29:00'
created: '2019-05-09T17:57:29.520784'
revision_date: '2020-03-15T04:22:22.595044'
assessment_id: 42ef50e2-cd57-4959-81d7-b8040da62de2
topic_id: 9e798bd6-8754-478d-8d09-b4bccfab3cdf
topic_short_id: qv2B7jfQLf
topic_slug: nuuo-central-management-server-authenticated-arbitrary-file-download
akb_topic_url: https://attackerkb.com/topics/qv2B7jfQLf/nuuo-central-management-server-authenticated-arbitrary-file-download
akb_assessment_url: https://attackerkb.com/topics/qv2B7jfQLf/nuuo-central-management-server-authenticated-arbitrary-file-download#42ef50e2-cd57-4959-81d7-b8040da62de2
author_ratings:
  attacker-value: 3
  confidence-in-ratings: 3
  exploitability: 2
  offensive-application: not sure
  urgent-to-patch: 3
---

# Nuuo Central Management Server Authenticated Arbitrary File Download

*Assessment by jrobles-r7, archived from [AttackerKB](https://attackerkb.com/topics/qv2B7jfQLf/nuuo-central-management-server-authenticated-arbitrary-file-download#42ef50e2-cd57-4959-81d7-b8040da62de2).*

---

## Details

Details from [module documentation](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/auxiliary/gather/nuuo_cms_file_download.md) in Metasploit.

The GETCONFIG verb is used by a CMS client to obtain configuration files and other resources from the CMS server. An example request is below:

```
GETCONFIG NUCM/1.0
FileName: <filename>
FileType: <number>
User-Session-No: <session-number>
```

The FileType determines the directory where the file will be downloaded from. "FileType: 0" will download from the base installation directory (CMS_DIR), while "FileType: 1" will download from "<CMS_DIR>\Images\Map\". There are other defined FileType integers, but these have not been investigated in detail.

The vulnerability is in the "FileName" parameter, which accepts directory traversal (..\\..\\) characters. Therefore, this function can be abused to obtain any files off the file system, including:

- CMServer.cfg, a file zipped with the password "NUCMS2007!" that contains the usernames and passwords of all the system users (enabling a less privileged user to obtain the administrator's password)
- ServerConfig.cfg, another file zipped with the password "NUCMS2007!" that contains the SQL Server "sa" password as well the FTP server username and password
- Any other sensitive files in the drive where CMS Server is installed.

This module works in the following way:

- if a SESSION number is present, uses that to login
- if not, tries to authenticate with USERNAME and PASSWORD

Due to the lack of ZIP encryption support in Metasploit, the module prints a warning indicating that the archive cannot be unzipped in Msf.
