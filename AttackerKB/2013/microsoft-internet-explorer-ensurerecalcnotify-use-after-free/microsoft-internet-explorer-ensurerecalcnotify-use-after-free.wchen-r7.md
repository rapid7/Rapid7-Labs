---
title: Microsoft Internet Explorer EnsureRecalcNotify Use-After-Free
author: wchen-r7
score: 2
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2013-08-14T11:10:00'
created: '2019-09-12T18:08:00.039663'
revision_date: '2020-10-19T23:07:58.953474'
assessment_id: 1f720314-2636-487c-80fc-e964389b8b04
topic_id: c2a72919-3813-4486-acad-02857ada29e5
topic_short_id: f87AOw4TT2
topic_slug: microsoft-internet-explorer-ensurerecalcnotify-use-after-free
akb_topic_url: https://attackerkb.com/topics/f87AOw4TT2/microsoft-internet-explorer-ensurerecalcnotify-use-after-free
akb_assessment_url: https://attackerkb.com/topics/f87AOw4TT2/microsoft-internet-explorer-ensurerecalcnotify-use-after-free#1f720314-2636-487c-80fc-e964389b8b04
---

# Microsoft Internet Explorer EnsureRecalcNotify Use-After-Free

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/f87AOw4TT2/microsoft-internet-explorer-ensurerecalcnotify-use-after-free#1f720314-2636-487c-80fc-e964389b8b04).*

---

 Set innerHTML
[*] EBX after EnsureRecalcNotify is: 0x0998cff0

0998cff0  ???????? ???????? ???????? ????????
0998d000  ???????? ???????? ???????? ????????
0998d010  ???????? ???????? ???????? ????????
0998d020  ???????? ???????? ???????? ????????
0998d030  ???????? ???????? ???????? ????????
0998d040  ???????? ???????? ???????? ????????
0998d050  ???????? ???????? ???????? ????????
0998d060  ???????? ???????? ???????? ????????
```

Which is lated used in the crash (see ESI):

```
(d9c.694): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=0bcebd00 ebx=00000000 ecx=11cf98b5 edx=aa0082bb esi=0998cff0 edi=047fd70c
eip=6b8199cd esp=047fd6d0 ebp=047fd6e8 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
MSHTML!QIClassID+0x38:
6b8199cd 8b06            mov     eax,dword ptr [esi]  ds:0023:0998cff0=????????
```

This is because in the vulnerable version, EnsureRecalcNotify returns the invalid
reference, passes it to GetLineInfo, and later used in the crash:

```
.text:639F5549 loc_639F5549:                           ; CODE XREF: CDisplayPointer::MoveToMarkupPointer(IMarkupPointer *,IDisplayPointer *)+6Ej
.text:639F5549                 test    eax, eax
.text:639F554B                 jz      loc_6378185D
.text:639F5551                 push    1
.text:639F5553                 mov     edi, eax
.text:639F5555                 call    ?EnsureRecalcNotify@CElement@@QAEJH@Z ; CElement::EnsureRecalcNotify(int)
.text:639F555A                 lea     ecx, [esp+18h+var_8] ; After the EnsureRecalcNotify call, EBX is invalid
.text:639F555E                 push    ecx
.text:639F555F                 push    ebx
.text:639F5560                 call    GetLineInfo     ; To the crash
.text:639F5565                 jmp     loc_63908A6E
```

In the patched version, the return value of EnsureNotifyValue is checked before calling GetLineInfo:

```
.text:639F5213 loc_639F5213:                           ; CODE XREF: CDisplayPointer::MoveToMarkupPointer(IMarkupPointer *,IDisplayPointer *)+6Fj
.text:639F5213                 test    eax, eax
.text:639F5215                 jz      loc_63780DDD
.text:639F521B                 push    1
.text:639F521D                 mov     edi, eax
.text:639F521F                 call    ?EnsureRecalcNotify@CElement@@QAEJH@Z ; CElement::EnsureRecalcNotify(int)
.text:639F5224                 mov     edi, eax
.text:639F5226                 test    edi, edi
.text:639F5228                 js      loc_63907FAF    ; to RETN
.text:639F522E                 mov     edx, [ebp+arg_4]
.text:639F5231                 lea     ecx, [esp+18h+var_8]
.text:639F5235                 push    ecx
.text:639F5236                 push    edx
.text:639F5237                 call    GetLineInfo
.text:639F523C                 jmp     loc_63907F1E
```
