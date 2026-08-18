---
title: Advantech WebAccess Webvrpcs Service Opcode 80061 Stack Buffer Overflow
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2017-11-06T22:29:00'
created: '2019-09-12T18:07:28.870046'
revision_date: '2020-02-13T17:12:15.261772'
assessment_id: 91933be1-05fb-46f9-b515-c37b75848bad
topic_id: 805f2e7a-a864-4917-992a-dbe4465990fb
topic_short_id: pY1k679LXn
topic_slug: advantech-webaccess-webvrpcs-service-opcode-80061-stack-buffer-overflow
akb_topic_url: https://attackerkb.com/topics/pY1k679LXn/advantech-webaccess-webvrpcs-service-opcode-80061-stack-buffer-overflow
akb_assessment_url: https://attackerkb.com/topics/pY1k679LXn/advantech-webaccess-webvrpcs-service-opcode-80061-stack-buffer-overflow#91933be1-05fb-46f9-b515-c37b75848bad
---

# Advantech WebAccess Webvrpcs Service Opcode 80061 Stack Buffer Overflow

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/pY1k679LXn/advantech-webaccess-webvrpcs-service-opcode-80061-stack-buffer-overflow#91933be1-05fb-46f9-b515-c37b75848bad).*

---

The stack overflow happens in sub_10004BC8:

```
.text:10004BC8 ; int __cdecl sub_10004BC8(char *Format, char)
.text:10004BC8 sub_10004BC8    proc near               ;
.text:10004BC8                                         ;
.text:10004BC8
.text:10004BC8 lpWindowName    = dword ptr -818h
.text:10004BC8 hWnd            = dword ptr -814h
.text:10004BC8 lpClassName     = dword ptr -810h
.text:10004BC8 Args            = dword ptr -80Ch
.text:10004BC8 lpBaseAddress   = dword ptr -808h
.text:10004BC8 hFileMappingObject= dword ptr -804h
.text:10004BC8 Dest            = byte ptr -800h
.text:10004BC8 Format          = dword ptr  8
.text:10004BC8 arg_4           = byte ptr  0Ch
.text:10004BC8
.text:10004BC8                 push    ebp
.text:10004BC9                 mov     ebp, esp
.text:10004BCB                 sub     esp, 818h
.text:10004BD1                 mov     [ebp+lpWindowName], offset aDebugScreen1    ; "Debug Screen1"
.text:10004BDB                 mov     [ebp+lpClassName], offset aDebugwclass1     ; "debugWClass1"
.text:10004BE5                 lea     eax, [ebp+arg_4]
.text:10004BE8                 mov     [ebp+Args], eax
.text:10004BEE                 mov     ecx, [ebp+Args]
.text:10004BF4                 push    ecx                                         ; Args
.text:10004BF5                 mov     edx, [ebp+Format]
.text:10004BF8                 push    edx                                         ; Format
.text:10004BF9                 lea     eax, [ebp+Dest]
.text:10004BFF                 push    eax                                         ; Dest
.text:10004C00                 call    ds:vsprintf                                 ; overflow
```

The corresponding IDL is below:

```
[
 uuid(5d2b62aa-ee0a-4a95-91ae-b064fdb471fc),
 version(1.0)
]

interface target_interface
{

/* opcode: 0x01, address: 0x00401260 */

void sub_401260 (
 [in] handle_t  arg_1,
 [in] long  arg_2,
 [in] long  arg_3,
 [in] long  arg_4,
 [in][ref][size_is(arg_4)] char * arg_5,
 [out][ref] long * arg_6
);

}
```
