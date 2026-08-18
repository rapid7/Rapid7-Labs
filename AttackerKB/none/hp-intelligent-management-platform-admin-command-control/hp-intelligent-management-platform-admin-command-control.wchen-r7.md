---
title: HP Intelligent Management Platform Admin Command Control
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
created: '2019-09-12T18:07:26.728109'
revision_date: '2020-02-13T17:12:15.917309'
assessment_id: 1d2c25d6-ade8-4680-a1c8-d79dfd295a26
topic_id: 3d9171e8-3bf8-4404-a3cd-f60dd9fe97d9
topic_short_id: 2vqhgmiJe6
topic_slug: hp-intelligent-management-platform-admin-command-control
akb_topic_url: https://attackerkb.com/topics/2vqhgmiJe6/hp-intelligent-management-platform-admin-command-control
akb_assessment_url: https://attackerkb.com/topics/2vqhgmiJe6/hp-intelligent-management-platform-admin-command-control#1d2c25d6-ade8-4680-a1c8-d79dfd295a26
---

# HP Intelligent Management Platform Admin Command Control

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/2vqhgmiJe6/hp-intelligent-management-platform-admin-command-control#1d2c25d6-ade8-4680-a1c8-d79dfd295a26).*

---

-|
```

UDP 1810 = UAM background port for listening to commands from the foreground

```
0042E597   . FF15 5C015800  CALL DWORD PTR DS:[<&WS2_32.#2>]         ; \bind

Each recvfrom() receives a max of 4132 bytes
0042E6A8   . 52             PUSH EDX                                 ; /pFromLen
0042E6A9   . 50             PUSH EAX                                 ; |pFrom
0042E6AA   . 53             PUSH EBX                                 ; |Flags
0042E6AB   . 8D8C24 BC7B000>LEA ECX,DWORD PTR SS:[ESP+7BBC]          ; |
0042E6B2   . 68 24100000    PUSH 1024                                ; |BufSize = 1024 (4132.)
0042E6B7   . 51             PUSH ECX                                 ; |Buffer
0042E6B8   . 57             PUSH EDI                                 ; |Socket
0042E6B9   . C78424 0C01000>MOV DWORD PTR SS:[ESP+10C],10            ; |
0042E6C4   . FF15 6C015800  CALL DWORD PTR DS:[<&WS2_32.#17>]        ; \recvfrom

After the packet is received, it begins to check the packet size:
0042E6F8   > 81FE 00100000  CMP ESI,1000                             ;If larger than 0x1000, bounce
0042E6FE   . 0F8F E12F0000  JG uam.004316E5
0042E704   . 83FE 14        CMP ESI,14                               ;If less than 0x14, bounce
```

After the packet gets past the size checks, it checks for a "Command ID":

```
0042E850   . 817D 00 213D10>CMP DWORD PTR SS:[EBP],F7103D21
```

When the "Command ID" matches, it begins checking the "Command Type":

```
0042E85F   . E8 D42BFDFF    CALL uam.00401438                        ;  Extract command type
```

The following "Command Types" are available:

```
0x101 = Echo request              (See 0x0042E88B)
0x102 = Echo reply                (See 0x0042E899)
0x201 = Restart command           (See 0x0042E87A)
0x202 = Stop command              (See 0x0042E95D)
0x303 = get user offline command  (See 0x0042E9D6)
0x401 = Re-configure plat request (See 0x0042E9E1)
0x501 = get pause resume command  (See 0x0042E9C5)
0x601 = user payment command      (See 0x00431563)
```
Some settings related to logging that can trigger different code paths (ead.TBL_PARAMETE):

```
1020	PUB_LOG_STORE_TIME	1	30	Days	1	365	Log Lifetime
1310	ENABLE_AUTH_FAIL_SYSLOG	1	0	NULL	0	1	If enable sending the syslog of authentication failed
1311	ENABLE_SAFELOG_SYSLOG	1	0	NULL	0	1	If enable sending the syslog of safelog
1312	SYSLOG_SERVER_IP	2	 	NULL	0	4294967295	syslog server IP
2060	EAD_LOG_ATT_SUCCEED	1	0	NULL	0	1	If Log Successful Authentication(1-Yes;0-No)
2070	EAD_LOG_CLEAN_VIRUS	1	1	NULL	0	1	If Log Virus Cleanup on Client(1-Yes;0-No)
2170	EAD_LOG_LEVEL	1	3	NULL	0	4	Policy Server Log Level
3000	EAD_REPORT_SAFE_LOG	1	1	NULL	0	1	If the safe log is reported , 1: yes , 0: no
3020	PUB_LOG_LEVEL	1	2	NULL	0	4	Log Level
3030	PUB_LOG_PATH	3	C:\Program Files\iMC\uam\log	NULL	NULL	NULL	Log File Path
3040	PUB_LOG_RESERVE_TIME	1	30	Days	1	365	Log And Backup File Lifetime
3100	PORTAL_SERVER_LOG_LEVEL	1	3	NULL	1	6	Portal Log Level
3110	PORTAL_SERVER_LOG_PATH	3	C:\Program Files\iMC\portal\logs\	NULL	NULL	NULL	Portal Log File Path
3140	PORTAL_LOG_LIST_LENGTH	1	1000	NULL	1	65535	Portal Log Queue Length
3170	PUB_AUTH_FAIL_LOG_TIME	1	90	day	1	365	Auth Fail Log reserve Time
3320	PUB_ENDUSER_MODIFY_PASSWD_LIMIT	0	0	NULL	0	1	Allow User Login(1-YES;0-NO)
4053	SSV_TOP_LOGO	3	login_3com.gif	NULL	NULL	NULL	the top image name in the first page of SSV
4054	SSV_BOTTOM_LOGO	3	3com_about.gif	NULL	NULL	NULL	the bottom image name in the first page of SSV
4055	SSV_ABOUT_LOGO	3	logo_top_3com.gif	NULL	NULL	NULL	the top logo name in the page after a user logging in
7008	MSCHAPV2_LOG_LEVEL	3	3	NULL	NULL	NULL	MSChapV2 log level
```

An example of how to update a setting:

```
UPDATE [ead].[ead].[TBL_PARAMETER] SET VALUE=5 where PARAMETER_NAME='PUB_LOG_LEVEL'
```
