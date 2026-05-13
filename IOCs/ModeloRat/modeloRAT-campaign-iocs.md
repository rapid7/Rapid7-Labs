# ModeloRAT Indicators of Compromise


## Dropper Archive

| Filename | MD5 | Size |
|---|---|---|
| `vuzggemyofftzpk6.zip` | `b98a753a6d0f533e5586555ca2e6d2c5` | 34,571,645 B |

---

## Python Samples

| Filename | Role | MD5 | SHA1 | SHA256 | TLSH | Size |
|---|---|---|---|---|---|---|
| `collector.py` | Recon stage 1; writes `%TEMP%\configA.json` | `fd9ca0ac0a8f3321668e21b3472fba4a` | `1e2d57f0b8f2f6a8ba415e01540e6548e8467874` | `6eac0014a61b894bfac5cf8dd5d6172726c07472a9637f6394d31d5587f518d6` | `T10f3218597f6b581953fa812e0881c592eb5c9f4310166723b0fd4a683fb35b286f06bf` | 11,870 B |
| `PCDr6967.py` | SOCKS proxy / C2 tunnel | `fa357e3111dc7ee05e3a726317768b4a` | `a8026b0cebd93d1812bcf783a30614c3efd6e138` | `09022780adff8324a2b693f47179e497126fc9fd87952c5c09f048e1e38eec77` | `T1ad135b50ad26a455d27bc80d08a3fa67d7cb1203563e8633b5ac5fe47fb306450b2dae` | 44,829 B |
| `Microsoft5237.py` / `internal.py` *(build 1)* | RAT C2 agent; schtask `TempLogA` as SYSTEM | `b36d42bbb3c007854d1f17e3b3b3570d` | `7b03ee84884a2ac221323333e99def1015add7bd` | `930263c0843744e269b615fb2ec79f83d7bd8b2cbf75e31fd5ea6c1aaa4e48fd` | `T122437c01ac0c6850d637940e8dc7d867d3996b832a6b4d96fffc44670f38af54a90ee8` | 55,196 B |
| `Microsoft5237.py` *(build 2)* | RAT C2 agent — obfuscation variant | — | — | `b00c1cbcfb98d2618a5c2ccb311da94f3c57709a397be6c8de29839f4e943976` | — | — |
| `Pmanager.py` | Unanalyzed | `c029b2b8c6271a74668a40cad2eb5db7` | `308dc4d38b6f7a5b1156c9d2bae979e69dfc9110` | `66f9c0eb64db7fac127d3d6d2a5a65de6b00bf2b78146a5acecdba2c628b1753` | `T199738d109f0a1d88d97f644f0927d8cbc38ecb13192a6817b6feb6625f3452146e1e7e` | 78,903 B |
| `USOShared1297.py` | Unanalyzed | `a67bdbb2a34bb9737aabd5588ce19f87` | `7fdb629cf4b3aa1cf4426f8ed1af917b241ac6f9` | `c2fa3e390855c874e3f3b7ca53e2bebd91c76b58ed913c5e96187bc52eb639f6` | `T1a1834b499d0f98861a7b880d4c6fe40bd34a1e23340dbdabf57e9064af396239570dbc` | 87,650 B |


## DLL Samples

---

`ssss.dll` - loader
md5: ea5eb6c65e21ff97f567586bb75b6420
sha256: b00c1cbcfb98d2618a5c2ccb311da94f3c57709a397be6c8de29839f4e943976

`testdllLPE.dll` - exploit CVE-2023-36036
md5: cce70fc48006d647f208fc0e01f99b61
sha256: d84245f3a374dd5eff8ecfdfad39077d76331fde799e5306430d0fc788db7f1d

`pdb C:\Users\username456\source\repos\testdllLPE\x64\Release\testdllLPE.pdb`

---

`com6848.dll` - loader
md5:c0e3441690fc7254a6288305137dd27c
sha256:30e5a6c982396cdf3157195b540f75096869baa8570f66fab88c07c161be27f0

`stage2.dll` - fake Windows 10 lock screen
md5: e75d877f6cecebb75326b761fbfa2f15
sha256:f5b2dbd8ec9671c0261f093ebc5f3d35920b592458a3b800cc946265111e67d0

---

## Network — C2 Infrastructure

| IP | ASN | Description |
|---|---|---|---|
| `64.190.113.187` | AS399629 BL Networks | C2  | 
| `96.9.125.29` | AS399629 BL Networks | C2  | 
| `144.172.99.68` | AS399629 BL Networks | C2  | 
| `46.225.231.170` | AS399629 BL Networks | C2  | 
| `140.82.6.45` | AS399629 BL Networks | C2  | 
| `64.94.85.158` | — | C2 (aiohttp :80) | 
| `144.172.88.18` | — | C2  | Medium — hardcoded in agent |
| `144.172.111.49` | — | C2  | Medium |
| `45.76.241.51` | AS20473 Vultr | C2  | 
| `149.28.96.170` | AS20473 Vultr | C2  |
| `87.120.186.229` | — | C2  | 
| `104.194.152.246` | — | C2  | 
| `207.246.114.50` | — | C2  | 
| `149.248.78.202` | — | C2  | 
| `45.59.122.231` | — | Delivery staging 

## Network — Ports

| Port | Protocol | Comment |
|---|---|---|
| `50504` | TCP outbound | C2 registration — PING/PONG handshake, dynamic port assignment |
| `50508` | TCP outbound | C2 registration — alternate |
| `60503` | TCP outbound | File transfer / screenshot exfil |



## Delivery 

```
https://www.dropbox[.]com/scl/fi/[REDACTED]/vuzggemyofftzpk6.zip?rlkey=elabnna8r5omwglaq4feay6ui&st=op5i7lea&dl=1

```

---

## Host Artifacts

| Type | Value | Notes |
|---|---|---|
| File | `%APPDATA%\Winp.zip` | Staged payload archive |
| Directory | `%APPDATA%\WPy64-31401\` | Portable WinPython runtime |
| File | `%TEMP%\configA.json` | Recon output from `collector.py` |
| Scheduled Task | `TempLogA` | Runs `pythonw.exe Microsoft5237.py` as SYSTEM |
| Registry | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager\PLURIBUS` | Fake cloud sync root registration |
| PDB path | `%USERPROFILE%\source\repos\testdllLPE\x64\Release\testdllLPE.pdb` | Attacker dev artifact embedded in `testdllLPE.dll`|

---


## Pivoted Samples

| Filename | SHA256 |
|---|---|---|
| `technology.py` | `ccf295410a686bf26934abc100cc441031bf53adad6b9a63f13076cfe3752968` 
| `extentions.py` | `c739a0631b78a7924b08d8bf2bcf3117f84017ff48076daab9ebe535b9f1d741` 
| `SoftwareDistribution7003.py` | `29887da1c198192e2c99eb19595b9df844ee65018fa56ae2e0dd415c28d99872` 
| *(unknown filename)* | `851f50cd0a48f4782f6daa1de6c9a007c0cf2a8c7e873ad2ae0bb576f7d1cef6` 

Delivery 
hxxps://www[.]dropbox[.]com/scl/fi/np4h0kexqq5r9vlpzwg4d/rp?rlkey=fwg1koexylntccobyxaliju7w&st=3wxzp44k&dl=1
hxxps://uc24960754e01bf26006464b576a.dl[.]dropboxusercontent[.]com/cd/0/get/C5WO8pgOFVqkfohQJXu-eEpZj1XZijhO3XCSzjdTLYYY_sk_MoT7B3CKOaTFWaDSxQCAQS8GuLLOgb_whKMyaoBvEbBJDAFJsey084B821xeF9IF1-LXTZ5kI9EPzGQIovRyUHYYfQViXzEJi6Rx8nAk/file?dl=1
hxxps://www[.]dropbox[.]com/scl/fi/47adtn9jg5iyzpi6gn5m4/rp?rlkey=lqu5o2v1fd2nc3npzi11v6grk&st=606seho4&dl=1
hxxps://www[.]dropbox[.]com/scl/fi/ci131linqkhwlbs05sncm/technology.py?rlkey=uqcprm17563prpxp93ad4huex&st=t2696kyt&dl=1
---
