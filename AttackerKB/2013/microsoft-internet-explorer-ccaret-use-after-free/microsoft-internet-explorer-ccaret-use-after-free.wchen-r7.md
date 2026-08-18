---
title: Microsoft Internet Explorer CCaret Use-After-Free
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2013-09-11T14:03:00'
created: '2019-09-12T18:07:54.410402'
revision_date: '2020-02-13T17:12:08.286145'
assessment_id: 4b6213f9-c9ee-473e-81ef-e4202a4cb790
topic_id: f58d6172-bfa6-45f0-988f-c5aab3e06e3a
topic_short_id: P4Hh21lFJf
topic_slug: microsoft-internet-explorer-ccaret-use-after-free
akb_topic_url: https://attackerkb.com/topics/P4Hh21lFJf/microsoft-internet-explorer-ccaret-use-after-free
akb_assessment_url: https://attackerkb.com/topics/P4Hh21lFJf/microsoft-internet-explorer-ccaret-use-after-free#4b6213f9-c9ee-473e-81ef-e4202a4cb790
---

# Microsoft Internet Explorer CCaret Use-After-Free

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/P4Hh21lFJf/microsoft-internet-explorer-ccaret-use-after-free#4b6213f9-c9ee-473e-81ef-e4202a4cb790).*

---

This is from crash2, gflags enabled

Originally discovered by Corelanc0d3r, see:
https://www.corelan.be/index.php/2014/05/22/on-cve-2014-1770-zdi-14-140-internet-explorer-8-0day/

# Note

This was kept private until an official patch was out from Microsoft

```
0:008> r
eax=00000000 ebx=00000000 ecx=7c91003d edx=00155000 esi=0cc2ef38 edi=0cc2ef38
eip=63621339 esp=037cfb88 ebp=037cfba4 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
mshtml!CSelectionManager::EnsureEditContext+0x30:
63621339 837f1800        cmp     dword ptr [edi+18h],0 ds:0023:0cc2ef50=????????
0:008> !heap -p -a edi
    address 0cc2ef38 found in
    _DPH_HEAP_ROOT @ 151000
    in free-ed allocation (  DPH_HEAP_BLOCK:         VirtAddr         VirtSize)
                                    c6bc350:          cc2e000             2000
    7c927553 ntdll!RtlFreeHeap+0x000000f9
    6375bc86 mshtml!CSelectionManager::`vector deleting destructor'+0x00000022
    6375b528 mshtml!CSelectionManager::Release+0x0000001e
    6358c7b0 mshtml!CSelectionManager::DoPendingElementExit+0x00000211
    6358c61b mshtml!CSelectionManager::DoPendingTasks+0x00000019
    63621335 mshtml!CSelectionManager::EnsureEditContext+0x0000002c
    6361c2bd mshtml!CHTMLEditor::Notify+0x0000005a
    6361c270 mshtml!CHTMLEditorProxy::Notify+0x00000021
    6360feb4 mshtml!CDoc::NotifySelection+0x00000059
    63620f7f mshtml!CCaret::UpdateScreenCaret+0x000000dd
    63784934 mshtml!CCaret::DeferredUpdateCaretScroll+0x00000032
    6364de62 mshtml!GlobalWndOnMethodCall+0x000000fb
    6363c3c5 mshtml!GlobalWndProc+0x00000183
    7e418734 USER32!InternalCallWinProc+0x00000028
    7e418816 USER32!UserCallWinProcCheckWow+0x00000150
    7e4189cd USER32!DispatchMessageWorker+0x00000306
```

```
0:008> u
mshtml!CSelectionManager::EnsureEditContext+0x30:
63621339 837f1800        cmp     dword ptr [edi+18h],0
6362133d 0f8423a52300    je      mshtml!CSelectionManager::EnsureEditContext+0x36 (6385b866)
63621343 5f              pop     edi
63621344 c3              ret
63621345 85c0            test    eax,eax
63621347 7ddb            jge     mshtml!CSelectionManager::EnsureEditContext+0x16 (63621324)
63621349 ebf8            jmp     mshtml!CSelectionManager::EnsureEditContext+0x3b (63621343)
6362134b 85c0            test    eax,eax
0:008> k
ChildEBP RetAddr
037cfb88 6361d930 mshtml!CSelectionManager::EnsureEditContext+0x30
037cfba4 6361c2bd mshtml!CSelectionManager::Notify+0x3a
037cfbb8 6361c270 mshtml!CHTMLEditor::Notify+0x5a
037cfbd4 6360feb4 mshtml!CHTMLEditorProxy::Notify+0x21
037cfbf0 63620f7f mshtml!CDoc::NotifySelection+0x59
037cfd14 63784934 mshtml!CCaret::UpdateScreenCaret+0xdd
037cfd24 6364de62 mshtml!CCaret::DeferredUpdateCaretScroll+0x32
037cfd58 6363c3c5 mshtml!GlobalWndOnMethodCall+0xfb
037cfd78 7e418734 mshtml!GlobalWndProc+0x183
037cfda4 7e418816 USER32!InternalCallWinProc+0x28
037cfe0c 7e4189cd USER32!UserCallWinProcCheckWow+0x150
037cfe6c 7e418a10 USER32!DispatchMessageWorker+0x306
037cfe7c 02562ec9 USER32!DispatchMessageW+0xf
037cfeec 025048bf IEFRAME!CTabWindow::_TabWindowThreadProc+0x461
037cffa4 5de05a60 IEFRAME!LCIETab_ThreadProc+0x2c1
037cffb4 7c80b713 iertutil!CIsoScope::RegisterThread+0xab
037cffec 00000000 kernel32!BaseThreadStart+0x37
```


Without gflags

```
0:008> r
eax=41424344 ebx=03323060 ecx=7c91003d edx=00000014 esi=00234ec8 edi=0000000c
eip=63620f82 esp=0201fc00 ebp=0201fd14 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010286
mshtml!CCaret::UpdateScreenCaret+0xe0:
63620f82 8b08            mov     ecx,dword ptr [eax]  ds:0023:41424344=????????
0:008> u
mshtml!CCaret::UpdateScreenCaret+0xe0:
63620f82 8b08            mov     ecx,dword ptr [eax]
63620f84 8d54246c        lea     edx,[esp+6Ch]
63620f88 52              push    edx
63620f89 50              push    eax
63620f8a ff512c          call    dword ptr [ecx+2Ch]
63620f8d 33ff            xor     edi,edi
63620f8f 397c246c        cmp     dword ptr [esp+6Ch],edi
63620f93 0f84669e2100    je      mshtml!CCaret::UpdateScreenCaret+0xf3 (6383adff)
0:008> k
ChildEBP RetAddr
0201fd14 63784934 mshtml!CCaret::UpdateScreenCaret+0xe0
0201fd24 6364de62 mshtml!CCaret::DeferredUpdateCaretScroll+0x32
0201fd58 6363c3c5 mshtml!GlobalWndOnMethodCall+0xfb
0201fd78 7e418734 mshtml!GlobalWndProc+0x183
0201fda4 7e418816 USER32!InternalCallWinProc+0x28
0201fe0c 7e4189cd USER32!UserCallWinProcCheckWow+0x150
0201fe6c 7e418a10 USER32!DispatchMessageWorker+0x306
0201fe7c 00cb2ec9 USER32!DispatchMessageW+0xf
0201feec 00c548bf IEFRAME!CTabWindow::_TabWindowThreadProc+0x461
0201ffa4 5de05a60 IEFRAME!LCIETab_ThreadProc+0x2c1
0201ffb4 7c80b713 iertutil!CIsoScope::RegisterThread+0xab
0201ffec 00000000 kernel32!BaseThreadStart+0x37
```
