---
title: Novell Unicode Buffer Overflow
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
created: '2019-09-12T18:07:31.452526'
revision_date: '2020-02-13T17:12:14.576232'
assessment_id: ae181423-aad4-4381-aa21-4b90c4bc3a40
topic_id: 819deded-6f41-4990-97cd-f45d8441f09c
topic_short_id: m5qNwyiteJ
topic_slug: novell-unicode-buffer-overflow
akb_topic_url: https://attackerkb.com/topics/m5qNwyiteJ/novell-unicode-buffer-overflow
akb_assessment_url: https://attackerkb.com/topics/m5qNwyiteJ/novell-unicode-buffer-overflow#ae181423-aad4-4381-aa21-4b90c4bc3a40
---

# Novell Unicode Buffer Overflow

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/m5qNwyiteJ/novell-unicode-buffer-overflow#ae181423-aad4-4381-aa21-4b90c4bc3a40).*

---

-
[+] Processing arguments and criteria
    - Pointer access level : X
    - Pointer criteria : ['unicoderev']
[+] Generating module info table, hang on...
    - Processing modules
    - Done. Let's rock 'n roll.
[+] Querying 56 modules
    - Querying module NMCP32.DLL
*** ERROR: Module load completed but symbols could not be loaded for C:\WINDOWS\system32\xpsp2res.dll
    - Querying module urlmon.dll
    - Querying module msxml3.dll
    - Querying module CRYPT32.dll
    - Querying module MSASN1.dll
    - Querying module kernel32.dll
    - Querying module msvcrt.dll
    - Querying module GDI32.dll
    - Querying module ntdll.dll
    - Querying module nmcd32.dll
    - Querying module wshtcpip.dll
    - Querying module WS2_32.dll
    - Querying module SENSAPI.DLL
    - Querying module ATL.DLL
    - Querying module CRYPTUI.dll
    - Querying module WININET.dll
    - Querying module CLBCATQ.DLL
    - Querying module Secur32.dll
    - Querying module WSOCK32.dll
    - Querying module rsaenh.dll
    - Querying module WS2HELP.dll
    - Querying module ole32.dll
    - Querying module SHLWAPI.dll
    - Querying module hnetcfg.dll
    - Querying module NMCH32.DLL
    - Querying module USER32.dll
    - Querying module comdlg32.dll
    - Querying module IMAGEHLP.dll
    - Querying module shdocvw.dll
    - Querying module NMCLEN.DLL
    - Querying module WINTRUST.dll
    - Querying module COMRes.dll
    - Querying module cscui.dll
    - Querying module OLEAUT32.dll
    - Querying module NETAPI32.dll
    - Querying module SHELL32.dll
    - Querying module RPCRT4.dll
    - Querying module CSCDLL.dll
    - Querying module mlang.dll
    - Querying module NMCL32.exe
    - Querying module USERENV.dll
    - Querying module nmenv2.dll
    - Querying module COMCTL32.dll
    - Querying module MSCTF.dll
    - Querying module WLDAP32.dll
    - Querying module VERSION.dll
    - Querying module mswsock.dll
    - Querying module appHelp.dll
    - Querying module browseui.dll
    - Querying module NMCA32.DLL
    - Querying module RichEd20.Dll
    - Querying module UxTheme.dll
    - Querying module ADVAPI32.dll
    - Querying module LINKINFO.dll
    - Querying module SETUPAPI.dll
    - Querying module ntshrui.dll
    - Search complete, processing results
[+] Preparing output file 'jmp.txt'
    - (Re)setting logfile jmp.txt
Done. Found 0 pointers
[+] This mona.py action took 0:02:13.578000
```

* On the other hand, I've installed the linux client, but it's a Java software, so there isn't memory corruption, just a message warning about the malformed file
