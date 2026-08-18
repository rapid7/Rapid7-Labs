---
title: Oracle Document Capture BlackIceDevMode.ocx ActiveX Remote Code Execution Vulnerability
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2013-04-17T12:19:00'
created: '2019-09-12T18:07:08.932259'
revision_date: '2020-02-13T17:12:20.23539'
assessment_id: 89b7789b-e810-4837-b7bb-3b612470f544
topic_id: f60d7de2-5a45-4f4c-9637-7543b636e42b
topic_short_id: 1F6xTShLIg
topic_slug: oracle-document-capture-blackicedevmode-ocx-activex-remote-code-execution-vulnerability
akb_topic_url: https://attackerkb.com/topics/1F6xTShLIg/oracle-document-capture-blackicedevmode-ocx-activex-remote-code-execution-vulnerability
akb_assessment_url: https://attackerkb.com/topics/1F6xTShLIg/oracle-document-capture-blackicedevmode-ocx-activex-remote-code-execution-vulnerability#89b7789b-e810-4837-b7bb-3b612470f544
---

# Oracle Document Capture BlackIceDevMode.ocx ActiveX Remote Code Execution Vulnerability

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/1F6xTShLIg/oracle-document-capture-blackicedevmode-ocx-activex-remote-code-execution-vulnerability#89b7789b-e810-4837-b7bb-3b612470f544).*

---

.text:100021EA                 align 10h
.text:100021F0
.text:100021F0 loc_100021F0:                           ; CODE XREF: sub_10002140+A8j
.text:100021F0                                         ; sub_10002140+BD1j
.text:100021F0                 movzx   ecx, word ptr [eax]
.text:100021F3                 mov     [edx+eax], cx
.text:100021F7                 add     eax, 2
.text:100021FA                 test    cx, cx
.text:100021FD                 jnz     short loc_100021F0
```

edx points to a local variable, eax to the user controlled provided annotation.

Crash:

```
(d98.4cc): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** WARNING: Unable to verify checksum for C:\PROGRA~1\BLACKI~1\BLACKI~2\BLACKI~1\BLACKI~1.OCX
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\PROGRA~1\BLACKI~1\BLACKI~2\BLACKI~1\BLACKI~1.OCX -
eax=03719080 ebx=00000000 ecx=00000041 edx=fe906f80 esi=0201f1e0 edi=00000040
eip=100021f3 esp=0201f174 ebp=0201f38c iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
BLACKI_1!DllUnregisterServer+0xfc3:
100021f3 66890c02        mov     word ptr [edx+eax],cx    ds:0023:02020000=4d5a
0:008> db edx
0:008> db eax
03719080  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
03719090  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
037190a0  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
037190b0  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
037190c0  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
037190d0  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
037190e0  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
037190f0  41 00 41 00 41 00 41 00-41 00 41 00 41 00 41 00  A.A.A.A.A.A.A.A.
```

In this case the exception is due to a overflow of the stack space. Trying to write after stack generates an exception. But this situation is tricky to exploit in moden versions of IE because heap goes after stack... so generate an exception trends to be tricky. Will give a chance anyway.

On the other hand the vulnerable function is protected by stack cookies:

```
.text:1000221D                 xor     ecx, esp
.text:1000221F                 call    @__security_check_cookie@4 ; __security_check_cookie(x)
.text:10002224                 add     esp, 60h
.text:10002227                 retn    3Ch
.text:10002227 sub_10002140    endp
```

Finally doesn't look so bad for exploitation via seh overwrite, but bad luck because the OCX is safeseh = true :( So... sounds difficult to make it exploitable out of ie6/ie7
