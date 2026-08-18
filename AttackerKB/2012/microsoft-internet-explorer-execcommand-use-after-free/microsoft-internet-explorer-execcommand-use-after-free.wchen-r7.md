---
title: Microsoft Internet Explorer execCommand Use-After-Free
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2012-09-18T10:39:00'
created: '2019-09-12T18:07:35.704681'
revision_date: '2020-02-13T17:12:13.326323'
assessment_id: ef6e31af-7b85-41cd-878a-87756e8258f7
topic_id: 29a5ae08-0b9d-4482-a746-3b9f3cc56934
topic_short_id: edotEkpiFR
topic_slug: microsoft-internet-explorer-execcommand-use-after-free
akb_topic_url: https://attackerkb.com/topics/edotEkpiFR/microsoft-internet-explorer-execcommand-use-after-free
akb_assessment_url: https://attackerkb.com/topics/edotEkpiFR/microsoft-internet-explorer-execcommand-use-after-free#ef6e31af-7b85-41cd-878a-87756e8258f7
---

# Microsoft Internet Explorer execCommand Use-After-Free

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/edotEkpiFR/microsoft-internet-explorer-execcommand-use-after-free#ef6e31af-7b85-41cd-878a-87756e8258f7).*

---

.text:7625B0F2
.text:7625B0F2 loc_7625B0F2:                           ; CODE XREF: _MemAllocClear(x)+25j
.text:7625B0F2                                         ; _MemAllocClear(x)+33j ...
.text:7625B0F2                 push    [ebp+dwBytes]   ; dwBytes
.text:7625B0F5                 push    8               ; dwFlags
.text:7625B0F7                 push    _g_hProcessHeap ; hHeap
.text:7625B0FD                 call    ds:__imp__HeapAlloc@12 ; HeapAlloc(x,x,x)
.text:7625B103
.text:7625B103 loc_7625B103:                           ; CODE XREF: _MemAllocClear(x)+71j
.text:7625B103                 pop     edi
.text:7625B104                 pop     ebx
.text:7625B105                 leave
.text:7625B106                 retn    4
.text:7625B106 __MemAllocClear@4 endp
.text:7625B106
```
